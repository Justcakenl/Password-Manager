//! Memory protection for secrets.
//!
//! SECURITY-CRITICAL. This file contains the only `unsafe` code in the
//! project. What it does:
//!
//! 1. [`ZeroizingAllocator`]: a global allocator that overwrites every block
//!    of memory with zeros before it is released. This way no copies of
//!    passwords are left behind in freed memory (for example after a
//!    `String` or `Vec` grew and moved).
//! 2. [`SecureBuf`]: a fixed-size buffer that lives on its own memory pages,
//!    is kept out of swap with `mlock` (if the limit allows it), is kept out
//!    of core dumps, and is wiped when dropped.
//! 3. [`harden_process`]: disables core dumps and makes the process
//!    "non-dumpable", so other processes of the same user cannot peek into
//!    its memory via ptrace or `/proc/<pid>/mem`.
//!
//! Limitation: this is "best effort". The operating system, the terminal and
//! the clipboard can still keep copies. See the security review in the README.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, Ordering};

use zeroize::Zeroize;

/// Becomes `true` as soon as an `mlock` attempt failed (e.g. because of RLIMIT_MEMLOCK).
static MLOCK_FAILED: AtomicBool = AtomicBool::new(false);

/// Global allocator that wipes released memory first.
///
/// Activated in `main.rs` with `#[global_allocator]`.
pub struct ZeroizingAllocator;

// SAFETY: we pass everything on to the system allocator and only add the
// wiping before `dealloc`. `realloc` deliberately uses the default
// implementation (alloc + copy + dealloc), so the old block is wiped too.
unsafe impl GlobalAlloc for ZeroizingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: same contract as GlobalAlloc::alloc.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: same contract as GlobalAlloc::alloc_zeroed.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` was allocated by us with this `layout`, so
        // `layout.size()` bytes from `ptr` are valid and ours.
        unsafe {
            std::slice::from_raw_parts_mut(ptr, layout.size()).zeroize();
            System.dealloc(ptr, layout);
        }
    }
}

fn page_size() -> usize {
    // SAFETY: sysconf is always safe to call.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if size > 0 { size as usize } else { 4096 }
}

/// Error returned when a [`SecureBuf`] is full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapacityError;

/// Fixed-capacity buffer for secrets (keys, the decrypted vault).
///
/// - Lives on its own page-aligned memory pages, so `munlock` can never
///   accidentally unlock the page of another secret.
/// - Is kept out of swap with `mlock` when that works.
/// - Is kept out of core dumps with `MADV_DONTDUMP`.
/// - Never grows (so reallocation can never leave a copy behind).
/// - Is completely overwritten with zeros on `Drop`.
pub struct SecureBuf {
    ptr: NonNull<u8>,
    len: usize,
    cap: usize,
    layout: Layout,
    locked: bool,
}

// SAFETY: SecureBuf is the only owner of its memory (like Vec<u8>).
unsafe impl Send for SecureBuf {}
// SAFETY: shared references only give read access.
unsafe impl Sync for SecureBuf {}

impl SecureBuf {
    /// Create an empty buffer that can hold at most `capacity` bytes.
    pub fn with_capacity(capacity: usize) -> Self {
        let page = page_size();
        let size = capacity.max(1).div_ceil(page) * page;
        let layout = Layout::from_size_align(size, page).expect("valid layout");
        // SAFETY: layout has a size > 0.
        let raw = unsafe { std::alloc::alloc_zeroed(layout) };
        let Some(ptr) = NonNull::new(raw) else {
            std::alloc::handle_alloc_error(layout);
        };
        // SAFETY: ptr/size describe exactly the block we just received.
        let locked = unsafe { libc::mlock(ptr.as_ptr().cast(), size) } == 0;
        if !locked {
            MLOCK_FAILED.store(true, Ordering::Relaxed);
        }
        // SAFETY: same; a failing madvise is not a problem (just less protection).
        unsafe {
            libc::madvise(ptr.as_ptr().cast(), size, libc::MADV_DONTDUMP);
        }
        SecureBuf { ptr, len: 0, cap: capacity, layout, locked }
    }

    /// Create a buffer holding a copy of `data`.
    pub fn from_slice(data: &[u8]) -> Self {
        let mut buf = Self::with_capacity(data.len());
        buf.extend_from_slice(data).expect("capacity matches");
        buf
    }

    /// Create a buffer of `len` zero bytes (to be filled via `as_mut_slice`).
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

    /// Whether the memory is actually locked with `mlock`.
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: the first `len` bytes are initialized (alloc_zeroed).
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: see as_slice; we have exclusive access through &mut self.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    /// Append bytes; fails (without changing anything) if they do not fit.
    pub fn extend_from_slice(&mut self, data: &[u8]) -> Result<(), CapacityError> {
        if data.len() > self.cap - self.len {
            return Err(CapacityError);
        }
        // SAFETY: enough room was checked; source and destination do not overlap.
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), self.ptr.as_ptr().add(self.len), data.len());
        }
        self.len += data.len();
        Ok(())
    }

    /// Shorten the buffer; the dropped bytes are wiped immediately.
    pub fn truncate(&mut self, new_len: usize) {
        if new_len < self.len {
            // SAFETY: the range [new_len, len) lies within the block.
            unsafe {
                std::slice::from_raw_parts_mut(self.ptr.as_ptr().add(new_len), self.len - new_len).zeroize();
            }
            self.len = new_len;
        }
    }
}

impl Drop for SecureBuf {
    fn drop(&mut self) {
        // SAFETY: we wipe and release exactly the block we allocated.
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
        // Never show the contents.
        write!(f, "SecureBuf([HIDDEN; {} bytes])", self.len)
    }
}

/// Lets `serde_json::to_writer` write straight into protected memory.
impl io::Write for SecureBuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.extend_from_slice(buf)
            .map_err(|_| io::Error::new(io::ErrorKind::OutOfMemory, "SecureBuf is full"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Counts how many bytes are written without storing them.
/// Used to determine the exact size of a [`SecureBuf`] up front.
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

/// How much of the stack [`scrub_stack`] overwrites.
pub const STACK_SCRUB_BYTES: usize = 64 * 1024;

/// Overwrite the stack area just below the caller with zeros.
///
/// SECURITY: some library code keeps secrets in local variables (for
/// example Argon2's first hash H0 is computed from the password and the
/// key-file pepper by a BLAKE2b hasher on the stack). Stack memory is never
/// freed, so the global allocator cannot wipe it. Calling this right after
/// such a computation reuses the same stack area for a large zeroed array,
/// which overwrites what the deeper calls left behind. Best effort: it
/// covers [`STACK_SCRUB_BYTES`], far more than those calls use.
#[inline(never)]
pub fn scrub_stack() {
    let mut area = [0u8; STACK_SCRUB_BYTES];
    // `zeroize` uses volatile writes, so the compiler cannot skip them even
    // though the array is never read.
    area.zeroize();
    std::hint::black_box(&area);
}

/// Result of [`harden_process`], for `cakepass info`.
#[derive(Debug, Clone, Copy)]
pub struct Hardening {
    pub core_dumps_disabled: bool,
    pub non_dumpable: bool,
}

/// Disable core dumps and make the process non-dumpable.
///
/// Must be called as early as possible in `main`, before any secrets exist.
pub fn harden_process() -> Hardening {
    let limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: valid pointer to an initialized struct.
    let core_dumps_disabled = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } == 0;
    // SAFETY: PR_SET_DUMPABLE with 0 is a simple process flag.
    let non_dumpable = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0;
    Hardening { core_dumps_disabled, non_dumpable }
}

/// Whether an `mlock` attempt has failed so far.
pub fn mlock_failed() -> bool {
    MLOCK_FAILED.load(Ordering::Relaxed)
}

/// The current limit for locked memory (RLIMIT_MEMLOCK) in bytes.
/// `None` = unlimited or unknown.
pub fn memlock_limit() -> Option<u64> {
    let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: valid pointer to a struct that getrlimit fills in.
    if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lim) } != 0 || lim.rlim_cur == libc::RLIM_INFINITY
    {
        return None;
    }
    Some(lim.rlim_cur)
}

/// Try to lock a single page; used by `cakepass info`.
pub fn mlock_works() -> bool {
    SecureBuf::with_capacity(1).is_locked()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn securebuf_basics() {
        let mut b = SecureBuf::with_capacity(5);
        assert!(b.is_empty());
        b.extend_from_slice(b"abc").unwrap();
        assert_eq!(b.as_slice(), b"abc");
        assert_eq!(b.extend_from_slice(b"def"), Err(CapacityError));
        assert_eq!(b.as_slice(), b"abc", "a failed append changes nothing");
        b.extend_from_slice(b"de").unwrap();
        assert_eq!(b.as_slice(), b"abcde");
        b.truncate(2);
        assert_eq!(b.as_slice(), b"ab");
        assert_eq!(b.len(), 2);
    }

    #[test]
    fn securebuf_write_and_debug_hide_contents() {
        let mut b = SecureBuf::with_capacity(10);
        write!(b, "secret").unwrap();
        assert_eq!(b.as_slice(), b"secret");
        assert!(!format!("{b:?}").contains("secret"));
        assert!(write!(b, "far too much text").is_err());
    }

    #[test]
    fn securebuf_zero_capacity() {
        let b = SecureBuf::with_capacity(0);
        assert!(b.as_slice().is_empty());
        let z = SecureBuf::zeroed(3);
        assert_eq!(z.as_slice(), &[0, 0, 0]);
    }

    #[test]
    fn counting_writer_counts() {
        let mut c = CountingWriter::default();
        write!(c, "12345").unwrap();
        assert_eq!(c.0, 5);
    }
}
