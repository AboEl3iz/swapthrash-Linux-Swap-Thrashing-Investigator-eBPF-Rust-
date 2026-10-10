// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

mod hist;

use anyhow::{Context, Result};
use chrono::Local;
use clap::Parser;
use hist::{Histogram, TimeUnit};
use libbpf_rs::{Map, MapCore, ObjectBuilder, RingBufferBuilder};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

static BPF_ELF: &[u8] = include_bytes!("bpf/swapthrash.bpf.o");

#[derive(Parser, Debug)]
#[command(
    name = "swapthrash",
    author = "Karim <senior-kernel-engineer>",
    version = "1.0.0",
    about = "Investigate Linux swap thrashing by measuring page swap residency time as a histogram",
    long_about = "A high-performance eBPF tool designed to diagnose memory pressure and swap thrashing.\n\
                  It traces anonymous memory pages from the moment they are dispatched to the swap storage\n\
                  device (__swap_writepage) until they are faulted back into memory (swap_read_folio),\n\
                  plotting the distribution of swap residency time as a power-of-2 logarithmic histogram."
)]
struct Args {
    /// Output interval in seconds (default: 0 = summary on Ctrl-C)
    #[arg(short = 'i', long = "interval", default_value_t = 0)]
    interval: u64,

    /// Number of interval reports before exiting (0 = run indefinitely)
    #[arg(short = 'c', long = "count", default_value_t = 0)]
    count: u64,

    /// Display residency histogram in microseconds
    #[arg(short = 'u', long = "microseconds")]
    microseconds: bool,

    /// Display residency histogram in seconds
    #[arg(short = 's', long = "seconds")]
    seconds: bool,

    /// Show per-process breakdown of swap-ins
    #[arg(short = 'p', long = "per-process")]
    per_process: bool,

    /// Stream individual page residency events in real-time via BPF ring buffer
    #[arg(short = 'r', long = "realtime")]
    realtime: bool,

    /// Highlight / filter thrashing events with residency below this threshold in milliseconds
    #[arg(short = 't', long = "threshold-ms", default_value_t = 0)]
    threshold_ms: u64,

    /// Print cumulative totals instead of interval deltas
    #[arg(long = "cumulative")]
    cumulative: bool,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SwapStats {
    pub swap_out_count: u64,
    pub swap_in_count: u64,
    pub matched_count: u64,
    pub freed_count: u64,
    pub untracked_in_count: u64,
    pub thrash_count_100ms: u64,
    pub thrash_count_1s: u64,
    pub thrash_count_10s: u64,
    pub min_residency_ns: u64,
    pub max_residency_ns: u64,
    pub total_residency_ns: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ProcStat {
    pub comm: [i8; 16],
    pub swap_in_count: u64,
    pub thrash_count_1s: u64,
    pub total_residency_ns: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ProcKey {
    pub pid: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SwapEvent {
    pub timestamp_ns: u64,
    pub swp_val: u64,
    pub residency_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub comm: [i8; 16],
}

/// Bump RLIMIT_MEMLOCK to infinity so eBPF maps can be allocated
fn bump_memlock_rlimit() -> Result<()> {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let res = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if res != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EPERM) {
            eprintln!("Warning: Failed to increase RLIMIT_MEMLOCK: {}", err);
        }
    }
    Ok(())
}

/// Read all 64 per-CPU histogram buckets from hist_map, summing across online CPUs
fn read_histogram_buckets(hist_map: &Map) -> Result<[u64; 64]> {
    let mut buckets = [0u64; 64];

    for (i, bucket_val) in buckets.iter_mut().enumerate() {
        let key = (i as u32).to_ne_bytes();
        if let Some(percpu_vals) = hist_map.lookup_percpu(&key, libbpf_rs::MapFlags::empty())? {
            let mut sum = 0u64;
            for cpu_slice in percpu_vals {
                if cpu_slice.len() >= 8 {
                    let val = u64::from_ne_bytes(cpu_slice[..8].try_into().unwrap());
                    sum += val;
                }
            }
            *bucket_val = sum;
        }
    }

    Ok(buckets)
}

/// Read aggregate stats from stats_map
fn read_stats(stats_map: &Map) -> Result<SwapStats> {
    let key = 0u32.to_ne_bytes();
    if let Some(bytes) = stats_map.lookup(&key, libbpf_rs::MapFlags::empty())? {
        if bytes.len() >= std::mem::size_of::<SwapStats>() {
            let stats = unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const SwapStats) };
            return Ok(stats);
        }
    }
    Ok(SwapStats {
        swap_out_count: 0,
        swap_in_count: 0,
        matched_count: 0,
        freed_count: 0,
        untracked_in_count: 0,
        thrash_count_100ms: 0,
        thrash_count_1s: 0,
        thrash_count_10s: 0,
        min_residency_ns: 0,
        max_residency_ns: 0,
        total_residency_ns: 0,
    })
}

/// Helper to format duration in human-readable units
fn format_duration_ns(ns: u64) -> String {
    if ns == 0 {
        return "N/A".to_string();
    }
    if ns < 1_000 {
        format!("{} ns", ns)
    } else if ns < 1_000_000 {
        format!("{:.2} us", ns as f64 / 1_000.0)
    } else if ns < 1_000_000_000 {
        format!("{:.2} ms", ns as f64 / 1_000_000.0)
    } else {
        format!("{:.2} s", ns as f64 / 1_000_000_000.0)
    }
}

/// Print comprehensive swap statistics and thrashing severity assessment
fn print_stats_summary(stats: &SwapStats, prefix: &str) {
    println!("\n=== {} Swap Thrashing Diagnostics ===", prefix);
    println!("  Total Pages Swapped Out  : {:>10}", stats.swap_out_count);
    println!("  Total Pages Swapped In   : {:>10}", stats.swap_in_count);
    println!("  Matched Residency Events : {:>10}", stats.matched_count);
    println!("  Freed While in Swap      : {:>10}", stats.freed_count);
    println!("  Cold / Pre-existing In   : {:>10}", stats.untracked_in_count);

    if stats.matched_count > 0 {
        let avg_ns = stats.total_residency_ns / stats.matched_count;
        let pct_100ms = (stats.thrash_count_100ms as f64 / stats.matched_count as f64) * 100.0;
        let pct_1s = (stats.thrash_count_1s as f64 / stats.matched_count as f64) * 100.0;
        let pct_10s = (stats.thrash_count_10s as f64 / stats.matched_count as f64) * 100.0;

        println!("\n--- Swap Residency Latency ---");
        println!("  Min Residency Duration   : {}", format_duration_ns(stats.min_residency_ns));
        println!("  Avg Residency Duration   : {}", format_duration_ns(avg_ns));
        println!("  Max Residency Duration   : {}", format_duration_ns(stats.max_residency_ns));

        println!("\n--- Thrashing Severity Assessment ---");
        println!(
            "  Critical Thrashing (< 100ms) : {:>8} ({:>5.1}%)",
            stats.thrash_count_100ms, pct_100ms
        );
        println!(
            "  Severe Thrashing   (< 1s)    : {:>8} ({:>5.1}%)",
            stats.thrash_count_1s, pct_1s
        );
        println!(
            "  Moderate Thrashing (< 10s)   : {:>8} ({:>5.1}%)",
            stats.thrash_count_10s, pct_10s
        );

        if pct_100ms > 25.0 || pct_1s > 50.0 {
            println!("\n  [!] CRITICAL ALERT: SYSTEM IS ACTIVELY THRASHING!");
            println!("      Over 50% of pages swapped in were evicted less than 1 second ago.");
            println!("      Active working set exceeds available physical memory.");
        } else if pct_1s > 20.0 {
            println!("\n  [*] WARNING: ELEVATED SWAP THRASHING DETECTED.");
            println!("      Moderate rate of short-lived swap residency observed.");
        } else {
            println!("\n  [+] HEALTHY: Low thrashing ratio. Pages remain cold on swap.");
        }
    } else {
        println!("\n  No matched residency cycles completed in this window.");
    }
}

/// Print per-process breakdown of swap-ins
fn print_process_breakdown(proc_map: &Map) -> Result<()> {
    println!("\n--- Top Processes Triggering Swap-Ins ---");
    println!(
        "{:>8} {:<16} {:>10} {:>12} {:>14}",
        "PID", "COMM", "SWAP-INS", "THRASH(<1s)", "AVG RESIDENCY"
    );
    println!(
        "{:>8} {:<16} {:>10} {:>12} {:>14}",
        "--------", "----------------", "----------", "------------", "--------------"
    );

    let mut procs = Vec::new();

    for key_bytes in proc_map.keys() {
        if let Some(val_bytes) = proc_map.lookup(&key_bytes, libbpf_rs::MapFlags::empty())? {
            if val_bytes.len() >= std::mem::size_of::<ProcStat>() {
                let pkey: ProcKey = unsafe { std::ptr::read_unaligned(key_bytes.as_ptr() as *const _) };
                let pstat: ProcStat = unsafe { std::ptr::read_unaligned(val_bytes.as_ptr() as *const _) };

                let comm_bytes: Vec<u8> = pstat.comm.iter().map(|&c| c as u8).take_while(|&c| c != 0).collect();
                let comm = String::from_utf8_lossy(&comm_bytes).to_string();

                procs.push((pkey.pid, comm, pstat.swap_in_count, pstat.thrash_count_1s, pstat.total_residency_ns));
            }
        }
    }

    procs.sort_by(|a, b| b.3.cmp(&a.3).then_with(|| b.2.cmp(&a.2)));

    if procs.is_empty() {
        println!("  No active processes encountered swap-ins yet.");
        return Ok(());
    }

    for (pid, comm, count, thrash, total_ns) in procs.iter().take(15) {
        let avg_str = if *count > 0 {
            format_duration_ns(total_ns / count)
        } else {
            "N/A".to_string()
        };
        println!(
            "{:>8} {:<16} {:>10} {:>12} {:>14}",
            pid, comm, count, thrash, avg_str
        );
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    bump_memlock_rlimit()?;

    let unit = if args.microseconds {
        TimeUnit::Microseconds
    } else if args.seconds {
        TimeUnit::Seconds
    } else {
        TimeUnit::Milliseconds
    };

    println!("============================================================");
    println!("  swapthrash - Linux Swap Thrashing Investigator (eBPF/Rust)");
    println!("============================================================");
    println!("Tracing swap operations:");
    println!("  Swap-out hook: __swap_writepage (page sent to swap device)");
    println!("  Swap-in hook : swap_read_folio   (page faulted back from swap)");
    println!("  Residency    : Time page spent on swap device");
    println!("  Display Unit : {}", unit.suffix());
    if args.interval > 0 {
        println!("  Sampling     : Every {}s (count: {})", args.interval, if args.count == 0 { "unlimited".to_string() } else { args.count.to_string() });
    } else {
        println!("  Sampling     : Summary on Ctrl-C");
    }
    println!("Press Ctrl-C to stop.\n");

    // Open BPF object directly from embedded ELF bytes
    let open_obj = ObjectBuilder::default()
        .open_memory(BPF_ELF)
        .context("Failed to open BPF object from memory")?;

    // Load BPF programs and maps into the kernel
    let obj = open_obj
        .load()
        .context("Failed to load BPF programs into kernel. Verify root/CAP_BPF privileges.")?;

    // Attach all kprobes
    let mut links = Vec::new();
    for prog in obj.progs_mut() {
        let prog_name = prog.name().to_string_lossy().to_string();
        let link = prog
            .attach()
            .with_context(|| format!("Failed to attach probe: {}", prog_name))?;
        links.push(link);
    }

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .context("Error setting Ctrl-C signal handler")?;

    let hist_map = obj.maps().find(|m| m.name() == "hist_map").context("Map hist_map not found")?;
    let stats_map = obj.maps().find(|m| m.name() == "stats_map").context("Map stats_map not found")?;
    let proc_stats_map = obj.maps().find(|m| m.name() == "proc_stats_map").context("Map proc_stats_map not found")?;
    let events_ringbuf = obj.maps().find(|m| m.name() == "events_ringbuf").context("Map events_ringbuf not found")?;

    // If real-time event streaming was requested
    if args.realtime {
        println!("{:<12} {:>8} {:<16} {:>18} {:>16}", "TIME", "PID", "COMM", "SWAP_ENTRY", "RESIDENCY");
        println!("{:<12} {:>8} {:<16} {:>18} {:>16}", "------------", "--------", "----------------", "------------------", "----------------");

        let mut ringbuf_builder = RingBufferBuilder::new();
        ringbuf_builder
            .add(&events_ringbuf, |data| {
                if data.len() >= std::mem::size_of::<SwapEvent>() {
                    let ev: SwapEvent = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const _) };
                    let comm_bytes: Vec<u8> = ev.comm.iter().map(|&c| c as u8).take_while(|&c| c != 0).collect();
                    let comm = String::from_utf8_lossy(&comm_bytes);
                    let time_str = Local::now().format("%H:%M:%S%.3f").to_string();

                    println!(
                        "{:<12} {:>8} {:<16} {:#018x} {:>16}",
                        time_str,
                        ev.pid,
                        comm,
                        ev.swp_val,
                        format_duration_ns(ev.residency_ns)
                    );
                }
                0
            })
            .context("Failed to attach ring buffer callback")?;

        let ringbuf = ringbuf_builder.build().context("Failed to build ring buffer")?;

        while running.load(Ordering::SeqCst) {
            let _ = ringbuf.poll(Duration::from_millis(100));
        }

        println!("\nStreaming finished.");
        return Ok(());
    }

    let mut prev_buckets = [0u64; 64];
    let mut iterations = 0u64;

    if args.interval > 0 {
        while running.load(Ordering::SeqCst) {
            sleep(Duration::from_secs(args.interval));
            if !running.load(Ordering::SeqCst) {
                break;
            }

            iterations += 1;
            let current_buckets = read_histogram_buckets(&hist_map)?;
            let stats = read_stats(&stats_map)?;

            let display_buckets = if args.cumulative {
                current_buckets
            } else {
                let mut delta = [0u64; 64];
                for i in 0..64 {
                    delta[i] = current_buckets[i].saturating_sub(prev_buckets[i]);
                }
                delta
            };
            prev_buckets = current_buckets;

            let time_str = Local::now().format("%H:%M:%S").to_string();
            let hist = Histogram::new(display_buckets, unit);
            println!("{}", hist.render(&format!("Swap Residency Distribution @ {}", time_str)));

            let p50 = hist.percentile(50.0);
            let p90 = hist.percentile(90.0);
            let p99 = hist.percentile(99.0);
            if hist.total_count() > 0 {
                println!(
                    "  Percentiles ({}): p50 = {:.2}, p90 = {:.2}, p99 = {:.2}",
                    unit.suffix(),
                    unit.from_us(p50),
                    unit.from_us(p90),
                    unit.from_us(p99)
                );
            }

            print_stats_summary(&stats, &format!("[Interval {}]", iterations));

            if args.per_process {
                let _ = print_process_breakdown(&proc_stats_map);
            }

            if args.count > 0 && iterations >= args.count {
                break;
            }
        }
    } else {
        // Run indefinitely until Ctrl-C, then print summary
        println!("Tracing in progress... Press Ctrl-C to display swap residency histogram.");
        while running.load(Ordering::SeqCst) {
            sleep(Duration::from_millis(250));
        }
    }

    // Print final cumulative histogram and thrashing diagnostics
    println!("\n[!] Ctrl-C received. Generating cumulative report...");
    let final_buckets = read_histogram_buckets(&hist_map)?;
    let final_stats = read_stats(&stats_map)?;

    let final_hist = Histogram::new(final_buckets, unit);
    println!("{}", final_hist.render("Cumulative Swap Residency Distribution"));

    let p50 = final_hist.percentile(50.0);
    let p90 = final_hist.percentile(90.0);
    let p99 = final_hist.percentile(99.0);
    if final_hist.total_count() > 0 {
        println!(
            "  Percentiles ({}): p50 = {:.2}, p90 = {:.2}, p99 = {:.2}",
            unit.suffix(),
            unit.from_us(p50),
            unit.from_us(p90),
            unit.from_us(p99)
        );
    }

    print_stats_summary(&final_stats, "Cumulative");

    if args.per_process || final_stats.swap_in_count > 0 {
        let _ = print_process_breakdown(&proc_stats_map);
    }

    println!("\nDone.");
    Ok(())
}
