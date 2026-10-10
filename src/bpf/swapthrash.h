/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __SWAPTHRASH_H
#define __SWAPTHRASH_H

#define MAX_HIST_BUCKETS 64
#define COMM_LEN 16

/* Global statistics tracked by eBPF */
struct swap_stats {
    __u64 swap_out_count;      /* Total pages written out to swap */
    __u64 swap_in_count;       /* Total pages requested from swap */
    __u64 matched_count;       /* Swap-in events with tracked swap-out residency */
    __u64 freed_count;         /* Pages freed from swap before swap-in */
    __u64 untracked_in_count;  /* Swap-ins not seen during swap-out (pre-existing) */
    __u64 thrash_count_100ms;  /* Residency < 100 ms (critical thrashing) */
    __u64 thrash_count_1s;     /* Residency < 1 s (severe thrashing) */
    __u64 thrash_count_10s;    /* Residency < 10 s (moderate thrashing) */
    __u64 min_residency_ns;    /* Minimum observed swap residency */
    __u64 max_residency_ns;    /* Maximum observed swap residency */
    __u64 total_residency_ns;  /* Cumulative residency (for calculating average) */
};

/* Live event emitted via BPF ring buffer */
struct swap_event {
    __u64 timestamp_ns;
    __u64 swp_val;
    __u64 residency_ns;
    __u32 pid;
    __u32 tgid;
    char comm[COMM_LEN];
};

/* Key for per-process attribution */
struct proc_key {
    __u32 pid;
};

/* Value for per-process attribution */
struct proc_stat {
    char comm[COMM_LEN];
    __u64 swap_in_count;
    __u64 thrash_count_1s;
    __u64 total_residency_ns;
};

#endif /* __SWAPTHRASH_H */
