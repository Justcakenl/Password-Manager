//! Geheugenbescherming voor geheimen.
//!
//! BEVEILIGINGSKRITIEK. Dit bestand bevat de enige `unsafe` code van het
//! project. Wat het doet:
//!
//! 1. [`ZeroizingAllocator`]: een globale allocator die elk stukje geheugen
//!    met nullen overschrijft vóór het wordt teruggegeven. Zo blijven er geen
//!    kopieën van wachtwoorden achter in vrijgegeven geheugen (bijvoorbeeld
//!    na het groeien van een `String` of `Vec`).
//! 2. [`SecureBuf`]: een buffer met vaste grootte die op eigen geheugenpagina's
//!    staat, met `mlock` uit de swap wordt gehouden (als de limiet dat toelaat),
//!    uit core dumps wordt gehouden en bij opruimen gewist wordt.
//! 3. [`harden_process`]: zet core dumps uit en maakt het proces "niet-dumpbaar",
//!    zodat andere processen van dezelfde gebruiker niet in het geheugen kunnen
//!    meekijken via ptrace of `/proc/<pid>/mem`.
//!
//! Beperking: dit is "best effort". Het besturingssysteem, de terminal en het
//! klembord kunnen nog steeds kopieën bewaren. Zie de security-review in de README.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, Ordering};

use zeroize::Zeroize;

/// Wordt `true` zodra een `mlock`-poging mislukt is (bijv. door RLIMIT_MEMLOCK).
static MLOCK_FAILED: AtomicBool = AtomicBool::new(false);

/// Globale allocator die vrijgegeven geheugen eerst wist.
///
/// Wordt in `main.rs` geactiveerd met `#[global_allocator]`.
pub struct ZeroizingAllocator;

// SAFETY: we geven alles door aan de systeemallocator en voegen alleen het
// wissen toe vóór `dealloc`. `realloc` gebruikt bewust de standaard-
// implementatie (alloc + kopiëren + dealloc), zodat ook het oude blok gewist wordt.
unsafe impl GlobalAlloc for ZeroizingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: zelfde contract als GlobalAlloc::alloc.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: zelfde contract als GlobalAlloc::alloc_zeroed.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` is door ons toegewezen met deze `layout`, dus
        // `layout.size()` bytes vanaf `ptr` zijn geldig en van ons.
        unsafe {
            std::slice::from_raw_parts_mut(ptr, layout.size()).zeroize();
            System.dealloc(ptr, layout);
        }
    }
}

fn page_size() -> usize {
    // SAFETY: sysconf is altijd veilig om aan te roepen.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if size > 0 { size as usize } else { 4096 }
}

/// Fout als een [`SecureBuf`] vol is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapacityError;

/// Buffer met vaste capaciteit voor geheimen (sleutels, ontsleutelde kluis).
///
/// - Staat op eigen, pagina-uitgelijnde geheugenpagina's, zodat `munlock`
///   nooit per ongeluk de pagina van een ander geheim ontgrendelt.
/// - Wordt met `mlock` uit de swap gehouden als dat lukt.
/// - Wordt met `MADV_DONTDUMP` uit core dumps gehouden.
/// - Groeit nooit (dus nooit een achtergebleven kopie door herallocatie).
/// - Wordt bij `Drop` volledig met nullen overschreven.
pub struct SecureBuf {
    ptr: NonNull<u8>,
    len: usize,
    cap: usize,
    layout: Layout,
    locked: bool,
}

// SAFETY: SecureBuf is de enige eigenaar van zijn geheugen (zoals Vec<u8>).
unsafe impl Send for SecureBuf {}
// SAFETY: gedeelde referenties geven alleen leestoegang.
unsafe impl Sync for SecureBuf {}

impl SecureBuf {
    /// Maak een lege buffer die maximaal `capacity` bytes kan bevatten.
    pub fn with_capacity(capacity: usize) -> Self {
        let page = page_size();
        let size = capacity.max(1).div_ceil(page) * page;
        let layout = Layout::from_size_align(size, page).expect("geldige layout");
        // SAFETY: layout heeft een grootte > 0.
        let raw = unsafe { std::alloc::alloc_zeroed(layout) };
        let Some(ptr) = NonNull::new(raw) else {
            std::alloc::handle_alloc_error(layout);
        };
        // SAFETY: ptr/size beschrijven precies het blok dat we net kregen.
        let locked = unsafe { libc::mlock(ptr.as_ptr().cast(), size) } == 0;
        if !locked {
            MLOCK_FAILED.store(true, Ordering::Relaxed);
        }
        // SAFETY: idem; een mislukte madvise is niet erg (alleen minder bescherming).
        unsafe {
            libc::madvise(ptr.as_ptr().cast(), size, libc::MADV_DONTDUMP);
        }
        SecureBuf { ptr, len: 0, cap: capacity, layout, locked }
    }

    /// Maak een buffer met een kopie van `data`.
    pub fn from_slice(data: &[u8]) -> Self {
        let mut buf = Self::with_capacity(data.len());
        buf.extend_from_slice(data).expect("capaciteit klopt");
        buf
    }

    /// Maak een buffer van `len` nul-bytes (om in te schrijven via `as_mut_slice`).
    pub fn zeroed(len: usize) -> Self {
        let mut buf = Self::with_capacity(len);
        buf.len = len;
        buf
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn capacity(&self) -> usize {
        self.cap
    }

    /// Of het geheugen daadwerkelijk met `mlock` vergrendeld is.
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: de eerste `len` bytes zijn geïnitialiseerd (alloc_zeroed).
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: zie as_slice; we hebben exclusieve toegang via &mut self.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    /// Voeg bytes toe; faalt (zonder iets te wijzigen) als het niet past.
    pub fn extend_from_slice(&mut self, data: &[u8]) -> Result<(), CapacityError> {
        if data.len() > self.cap - self.len {
            return Err(CapacityError);
        }
        // SAFETY: er is genoeg ruimte gecontroleerd; bron en doel overlappen niet.
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), self.ptr.as_ptr().add(self.len), data.len());
        }
        self.len += data.len();
        Ok(())
    }

    /// Maak de buffer korter; de weggevallen bytes worden direct gewist.
    pub fn truncate(&mut self, new_len: usize) {
        if new_len < self.len {
            // SAFETY: bereik [new_len, len) ligt binnen het blok.
            unsafe {
                std::slice::from_raw_parts_mut(self.ptr.as_ptr().add(new_len), self.len - new_len)
                    .zeroize();
            }
            self.len = new_len;
        }
    }
}

impl Drop for SecureBuf {
    fn drop(&mut self) {
        // SAFETY: we wissen en geven precies het blok terug dat we toewezen.
        unsafe {
            std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.layout.size()).zeroize();
            if self.locked {
                libc::munlock(self.ptr.as_ptr().cast(), self.layout.size());
            }
            std::alloc::dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}

impl std::fmt::Debug for SecureBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Nooit de inhoud tonen.
        write!(f, "SecureBuf([VERBORGEN; {} bytes])", self.len)
    }
}

/// Zodat `serde_json::to_writer` rechtstreeks in beschermd geheugen schrijft.
impl io::Write for SecureBuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.extend_from_slice(buf)
            .map_err(|_| io::Error::new(io::ErrorKind::OutOfMemory, "SecureBuf vol"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Telt hoeveel bytes er geschreven worden zonder ze op te slaan.
/// Gebruikt om vooraf de exacte grootte van een [`SecureBuf`] te bepalen.
#[derive(Default)]
pub struct CountingWriter(pub usize);

impl io::Write for CountingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Resultaat van [`harden_process`], voor `kluis info`.
#[derive(Debug, Clone, Copy)]
pub struct Hardening {
    pub core_dumps_disabled: bool,
    pub non_dumpable: bool,
}

/// Zet core dumps uit en maak het proces niet-dumpbaar.
///
/// Moet zo vroeg mogelijk in `main` worden aangeroepen, vóór er geheimen zijn.
pub fn harden_process() -> Hardening {
    let limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: geldige pointer naar een geïnitialiseerde struct.
    let core_dumps_disabled = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } == 0;
    // SAFETY: PR_SET_DUMPABLE met 0 is een eenvoudige procesvlag.
    let non_dumpable = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0;
    Hardening { core_dumps_disabled, non_dumpable }
}

/// Of er tot nu toe een `mlock`-poging mislukt is.
pub fn mlock_failed() -> bool {
    MLOCK_FAILED.load(Ordering::Relaxed)
}

/// Probeer één pagina te vergrendelen; gebruikt door `kluis info`.
pub fn mlock_works() -> bool {
    SecureBuf::with_capacity(1).is_locked()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn securebuf_basis() {
        let mut b = SecureBuf::with_capacity(5);
        assert!(b.is_empty());
        b.extend_from_slice(b"abc").unwrap();
        assert_eq!(b.as_slice(), b"abc");
        assert_eq!(b.extend_from_slice(b"def"), Err(CapacityError));
        assert_eq!(b.as_slice(), b"abc", "mislukte toevoeging wijzigt niets");
        b.extend_from_slice(b"de").unwrap();
        assert_eq!(b.as_slice(), b"abcde");
        b.truncate(2);
        assert_eq!(b.as_slice(), b"ab");
        assert_eq!(b.len(), 2);
    }

    #[test]
    fn securebuf_write_en_debug_verbergt_inhoud() {
        let mut b = SecureBuf::with_capacity(10);
        write!(b, "geheim").unwrap();
        assert_eq!(b.as_slice(), b"geheim");
        assert!(!format!("{b:?}").contains("geheim"));
        assert!(write!(b, "te veel tekst").is_err());
    }

    #[test]
    fn securebuf_nul_capaciteit() {
        let b = SecureBuf::with_capacity(0);
        assert!(b.as_slice().is_empty());
        let z = SecureBuf::zeroed(3);
        assert_eq!(z.as_slice(), &[0, 0, 0]);
    }

    #[test]
    fn counting_writer_telt() {
        let mut c = CountingWriter::default();
        write!(c, "12345").unwrap();
        assert_eq!(c.0, 5);
    }
}
