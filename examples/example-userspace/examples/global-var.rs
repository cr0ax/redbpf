/// This example shows that global variable without proper synchronization has
/// incorrect value. On the other hand, the values of per-cpu map and global
/// variable updated by synchronized method are the same. It may take some
/// time to observe the incorrect value if the write-load is light.
///
/// Note that the values of per-cpu map and global variable differ from time to
/// time because of the timing of map-read.
use libc;
use std::process;
use std::time::Duration;
use tokio;
use tokio::select;
use tracing::{error, Level};
use tracing_subscriber::FmtSubscriber;

use redbpf::{load::Loader, Array, PerCpuArray};

#[repr(C)]
#[derive(Debug, Clone)]
struct Data {
    var: u64,
    var_wo_sync: u64,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    if unsafe { libc::geteuid() != 0 } {
        error!("You must be root to use eBPF!");
        process::exit(1);
    }

    let mut loaded = Loader::load(probe_code()).unwrap();
    loaded
        .kprobe_mut("incr_write_count")
        .expect("kprobe_mut error")
        .attach_kprobe("ksys_write", 0)
        .expect("error attach_kprobe");
    let global = Array::<Data>::new(loaded.map(".bss").expect("map not found"))
        .expect("can not initialize Array");
    let percpu_map =
        PerCpuArray::<u64>::new(loaded.map("PERCPU_MAP").expect("PERCPU_MAP not found"))
            .expect("can not initialize PerCpuArray");

    loop {
        let gval = global.get(0).expect("global var value");
        let pcpu_val = percpu_map.get(0).expect("percpu value");
        println!(
            "w/ sync, w/o sync, pcpu = {}, {}, {}",
            gval.var,
            gval.var_wo_sync,
            pcpu_val.iter().sum::<u64>()
        );
        select! {
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            _ = tokio::signal::ctrl_c() => { break }
        }
    }
}

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/global_var/global_var.elf"
    ))
}
