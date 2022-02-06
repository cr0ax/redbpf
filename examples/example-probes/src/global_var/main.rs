#![no_std]
#![no_main]
use core::sync::atomic::{AtomicU64, Ordering};
use redbpf_probes::kprobe::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[map]
static mut PERCPU_MAP: PerCpuArray<u64> = PerCpuArray::with_max_entries(1);

// global variable is shared between multiple cores so proper synchronization
// should be involved carefully.
static GLOBAL_VAR: AtomicU64 = AtomicU64::new(0);

// global variable without any synchronization mechanism. This results in wrong
// statistics.
static mut GLOBAL_VAR_INCORRECT: u64 = 0;

#[kprobe]
fn incr_write_count(_regs: Registers) {
    unsafe {
        GLOBAL_VAR.fetch_add(1, Ordering::Relaxed);
    }

    unsafe {
        GLOBAL_VAR_INCORRECT += 1;
    }

    unsafe {
        let val = PERCPU_MAP.get_mut(0).unwrap();
        *val += 1;
    }
}
