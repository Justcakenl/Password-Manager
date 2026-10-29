//! `kluis` – command-line interface (wordt in stap 3 gebouwd).

#[global_allocator]
static GLOBAL: kluis::secure_mem::ZeroizingAllocator = kluis::secure_mem::ZeroizingAllocator;

fn main() {
    let _ = kluis::secure_mem::harden_process();
}
