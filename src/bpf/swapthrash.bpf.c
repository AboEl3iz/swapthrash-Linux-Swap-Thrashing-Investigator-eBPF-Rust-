/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "swapthrash.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Configuration options set by userspace before load */
const volatile bool emit_events = false;
const volatile __u64 min_threshold_ns = 0;

/*
 * Hash map storing swap-out timestamps keyed by swp_entry_t.val.
 * BPF_MAP_TYPE_LRU_HASH ensures that if memory pressure is extreme,
 * cold pages or freed pages that never swap back in do not cause map exhaustion.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, __u64);         /* swp_entry_t.val */
    __type(value, __u64);       /* swap-out timestamp in nanoseconds */
} swap_out_events SEC(".maps");

/*
 * Histogram map of swap residency time.
 * Key: bucket index 0..63 (log2 of residency in microseconds).
 * PERCPU_ARRAY provides atomic, lockless increments across all CPUs.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_HIST_BUCKETS);
    __type(key, __u32);
    __type(value, __u64);
} hist_map SEC(".maps");

/* Global aggregate statistics */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct swap_stats);
} stats_map SEC(".maps");

/* Per-process swap-in tracking */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct proc_key);
    __type(value, struct proc_stat);
} proc_stats_map SEC(".maps");

/* Optional ring buffer for real-time swap residency events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events_ringbuf SEC(".maps");

/* Helper to safely extract swp_entry_t.val from struct folio */
static __always_inline __u64 get_folio_swap_val(struct folio *folio)
{
    if (!folio)
        return 0;

    __u64 swp_val = 0;
    if (bpf_core_field_exists(folio->swap.val)) {
        swp_val = BPF_CORE_READ(folio, swap.val);
    } else if (bpf_core_field_exists(folio->private)) {
        swp_val = (__u64)BPF_CORE_READ(folio, private);
    }
    return swp_val;
}

/* Helper to compute log2 for power-of-2 histogram buckets using only BPF ALU64 */
static __always_inline __u32 log2_u64(__u64 v)
{
    __u32 shift = 0;
    if (v == 0)
        return 0;

    if (v >= (1ULL << 32)) { v >>= 32; shift += 32; }
    if (v >= (1ULL << 16)) { v >>= 16; shift += 16; }
    if (v >= (1ULL << 8))  { v >>= 8;  shift += 8;  }
    if (v >= (1ULL << 4))  { v >>= 4;  shift += 4;  }
    if (v >= (1ULL << 2))  { v >>= 2;  shift += 2;  }
    if (v >= (1ULL << 1))  { shift += 1; }

    if (shift >= MAX_HIST_BUCKETS)
        shift = MAX_HIST_BUCKETS - 1;
    return shift;
}

/*
 * Hook 1: Swap-out initiation
 * Called when a folio is dispatched to the swap storage device.
 */
SEC("kprobe/__swap_writepage")
int BPF_KPROBE(trace_swap_writepage, struct folio *folio)
{
    __u64 swp_val = get_folio_swap_val(folio);
    if (!swp_val)
        return 0;

    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&swap_out_events, &swp_val, &ts, BPF_ANY);

    __u32 stats_key = 0;
    struct swap_stats *st = bpf_map_lookup_elem(&stats_map, &stats_key);
    if (st) {
        __sync_fetch_and_add(&st->swap_out_count, 1);
    }

    return 0;
}

/*
 * Hook 2: Swap-in initiation
 * Called when a folio needs to be read back into memory from swap storage.
 */
SEC("kprobe/swap_read_folio")
int BPF_KPROBE(trace_swap_read_folio, struct folio *folio)
{
    __u64 swp_val = get_folio_swap_val(folio);
    if (!swp_val)
        return 0;

    __u32 stats_key = 0;
    struct swap_stats *st = bpf_map_lookup_elem(&stats_map, &stats_key);
    if (st) {
        __sync_fetch_and_add(&st->swap_in_count, 1);
    }

    __u64 *start_ts = bpf_map_lookup_elem(&swap_out_events, &swp_val);
    if (!start_ts) {
        if (st) {
            __sync_fetch_and_add(&st->untracked_in_count, 1);
        }
        return 0;
    }

    __u64 now = bpf_ktime_get_ns();
    __u64 start = *start_ts;
    bpf_map_delete_elem(&swap_out_events, &swp_val);

    if (now <= start)
        return 0;

    __u64 residency_ns = now - start;

    /* Check optional filter threshold */
    if (min_threshold_ns > 0 && residency_ns < min_threshold_ns)
        return 0;

    /* Residency in microseconds for histogram indexing */
    __u64 residency_us = residency_ns / 1000;
    __u32 bucket = log2_u64(residency_us);

    __u64 *count = bpf_map_lookup_elem(&hist_map, &bucket);
    if (count) {
        *count += 1;
    }

    /* Update aggregate stats */
    if (st) {
        __sync_fetch_and_add(&st->matched_count, 1);
        __sync_fetch_and_add(&st->total_residency_ns, residency_ns);

        /* Thrashing indicators: short residency thresholds */
        if (residency_ns < 100000000ULL) {          /* < 100 ms */
            __sync_fetch_and_add(&st->thrash_count_100ms, 1);
        }
        if (residency_ns < 1000000000ULL) {         /* < 1 s */
            __sync_fetch_and_add(&st->thrash_count_1s, 1);
        }
        if (residency_ns < 10000000000ULL) {        /* < 10 s */
            __sync_fetch_and_add(&st->thrash_count_10s, 1);
        }

        /* Update min / max residency */
        if (st->min_residency_ns == 0 || residency_ns < st->min_residency_ns)
            st->min_residency_ns = residency_ns;
        if (residency_ns > st->max_residency_ns)
            st->max_residency_ns = residency_ns;
    }

    /* Track per-process metrics for the faulting task */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    struct proc_key pkey = { .pid = pid };
    struct proc_stat *pstat = bpf_map_lookup_elem(&proc_stats_map, &pkey);
    if (!pstat) {
        struct proc_stat new_stat = {};
        bpf_get_current_comm(&new_stat.comm, sizeof(new_stat.comm));
        new_stat.swap_in_count = 1;
        new_stat.total_residency_ns = residency_ns;
        if (residency_ns < 1000000000ULL)
            new_stat.thrash_count_1s = 1;
        bpf_map_update_elem(&proc_stats_map, &pkey, &new_stat, BPF_ANY);
    } else {
        __sync_fetch_and_add(&pstat->swap_in_count, 1);
        __sync_fetch_and_add(&pstat->total_residency_ns, residency_ns);
        if (residency_ns < 1000000000ULL)
            __sync_fetch_and_add(&pstat->thrash_count_1s, 1);
    }

    /* Emit ring buffer event if requested */
    if (emit_events) {
        struct swap_event *event = bpf_ringbuf_reserve(&events_ringbuf, sizeof(*event), 0);
        if (event) {
            event->timestamp_ns = now;
            event->swp_val = swp_val;
            event->residency_ns = residency_ns;
            event->pid = pid;
            event->tgid = (__u32)pid_tgid;
            bpf_get_current_comm(&event->comm, sizeof(event->comm));
            bpf_ringbuf_submit(event, 0);
        }
    }

    return 0;
}

/*
 * Hook 3: Page freed from swap
 * Called when a folio is freed from swap cache (e.g. process terminated or page unmapped).
 * This prevents stale entries from lingering if the page never swapped back in.
 */
SEC("kprobe/folio_free_swap")
int BPF_KPROBE(trace_folio_free_swap, struct folio *folio)
{
    __u64 swp_val = get_folio_swap_val(folio);
    if (!swp_val)
        return 0;

    __u64 *ts = bpf_map_lookup_elem(&swap_out_events, &swp_val);
    if (ts) {
        bpf_map_delete_elem(&swap_out_events, &swp_val);
        __u32 stats_key = 0;
        struct swap_stats *st = bpf_map_lookup_elem(&stats_map, &stats_key);
        if (st) {
            __sync_fetch_and_add(&st->freed_count, 1);
        }
    }

    return 0;
}
