// SPDX-License-Identifier: FSL-1.1
#![no_std]

use dlmalloc::GlobalDlmalloc;

#[global_allocator]
static ALLOCATOR: GlobalDlmalloc = GlobalDlmalloc;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}

// The component canonical ABI allocates host-to-guest return buffers through a
// `cabi_realloc` core export. wit-bindgen's runtime omits this export for
// wasm32-wasip2 targets, so the guest supplies it over its global allocator.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cabi_realloc(
    old_ptr: *mut u8,
    old_len: usize,
    align: usize,
    new_len: usize,
) -> *mut u8 {
    use core::alloc::{GlobalAlloc, Layout};

    let ptr = if old_len == 0 {
        if new_len == 0 {
            return align as *mut u8;
        }
        ALLOCATOR.alloc(Layout::from_size_align_unchecked(new_len, align))
    } else {
        debug_assert_ne!(new_len, 0, "non-zero old_len requires non-zero new_len!");
        ALLOCATOR.realloc(
            old_ptr,
            Layout::from_size_align_unchecked(old_len, align),
            new_len,
        )
    };
    if ptr.is_null() {
        core::arch::wasm32::unreachable();
    }
    ptr
}

wit_bindgen::generate!({
    world: "lock-script",
    path: "wit/wacc.wit",
});

// The genesis first-lock guest: verifies that the entry was signed with the
// ephemeral VLAD key, matching the behavior of the legacy `first.wast` module
// fixture.
struct Component;

impl Guest for Component {
    fn move_every_zig() -> i32 {
        use crate::cryptid::wacc::host::check_signature;

        if check_signature("/vlad/key", "/entry/") {
            1
        } else {
            0
        }
    }
}

export!(Component);