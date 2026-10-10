// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

use std::fmt::Write as _;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeUnit {
    Microseconds,
    Milliseconds,
    Seconds,
}

impl TimeUnit {
    pub fn suffix(&self) -> &'static str {
        match self {
            Self::Microseconds => "us",
            Self::Milliseconds => "ms",
            Self::Seconds => "s",
        }
    }

    pub fn from_us(&self, us: f64) -> f64 {
        match self {
            Self::Microseconds => us,
            Self::Milliseconds => us / 1_000.0,
            Self::Seconds => us / 1_000_000.0,
        }
    }
}

/// Formats and renders power-of-2 logarithmic histograms for swap residency.
pub struct Histogram {
    /// 64 buckets (bucket index = log2(residency in microseconds))
    pub buckets: [u64; 64],
    pub unit: TimeUnit,
}

impl Histogram {
    pub fn new(buckets: [u64; 64], unit: TimeUnit) -> Self {
        Self { buckets, unit }
    }

    pub fn total_count(&self) -> u64 {
        self.buckets.iter().sum()
    }

    /// Calculate estimated percentile (e.g. 50.0 for p50, 99.0 for p99) in microseconds
    pub fn percentile(&self, p: f64) -> f64 {
        let total = self.total_count();
        if total == 0 {
            return 0.0;
        }

        let target = ((p / 100.0) * total as f64).ceil() as u64;
        let mut accum = 0u64;

        for (i, &count) in self.buckets.iter().enumerate() {
            accum += count;
            if accum >= target {
                // Midpoint of bucket range [2^i, 2^(i+1)) in microseconds
                let low = if i == 0 { 0.0 } else { (1u64 << (i - 1)) as f64 };
                let high = (1u64 << i) as f64;
                return (low + high) / 2.0;
            }
        }

        // Return highest bucket value if exhausted
        (1u64 << 63) as f64
    }

    /// Render standard ASCII histogram table
    pub fn render(&self, title: &str) -> String {
        let total = self.total_count();
        let mut out = String::new();

        writeln!(&mut out, "\n--- {} ---", title).unwrap();
        if total == 0 {
            writeln!(&mut out, "No swap residency events recorded during this period.").unwrap();
            return out;
        }

        let max_val = *self.buckets.iter().max().unwrap_or(&0);
        let max_bar_width = 36usize;

        // Find the index of the first and last non-zero buckets to avoid printing 40 empty rows
        let first_idx = self.buckets.iter().position(|&c| c > 0).unwrap_or(0);
        let last_idx = self.buckets.iter().rposition(|&c| c > 0).unwrap_or(0);

        // Include 1 bucket of context before and after if possible
        let start_idx = first_idx.saturating_sub(1);
        let end_idx = (last_idx + 1).min(self.buckets.len() - 1);

        let unit_str = self.unit.suffix();
        writeln!(
            &mut out,
            "{:>16} : {:<8} {:<38} {:>6}",
            format!("Residency ({})", unit_str),
            "Count",
            "Distribution",
            "Pct"
        )
        .unwrap();
        writeln!(
            &mut out,
            "{:>16} : {:<8} {:<38} {:>6}",
            "----------------", "--------", "--------------------------------------", "------"
        )
        .unwrap();

        for i in start_idx..=end_idx {
            let count = self.buckets[i];
            let low_us = if i == 0 { 0.0 } else { (1u64 << (i - 1)) as f64 };
            let high_us = (1u64 << i) as f64;

            let low_converted = self.unit.from_us(low_us);
            let high_converted = self.unit.from_us(high_us);

            let range_str = if self.unit == TimeUnit::Seconds && high_converted < 1.0 {
                format!("{:.2} -> {:.2}", low_converted, high_converted)
            } else if low_converted >= 100.0 || high_converted >= 100.0 {
                format!("{:.0} -> {:.0}", low_converted, high_converted)
            } else {
                format!("{:.1} -> {:.1}", low_converted, high_converted)
            };

            let bar_len = if max_val > 0 {
                ((count as f64 / max_val as f64) * max_bar_width as f64).round() as usize
            } else {
                0
            };
            let bar = "@".repeat(bar_len);

            let pct = (count as f64 / total as f64) * 100.0;

            // Highlight thrashing severity based on residency duration
            // Pages returning in < 1 second (1_000_000 us) are strong indicators of thrashing
            let marker = if high_us <= 100_000.0 && count > 0 {
                " [CRITICAL THRASH]"
            } else if high_us <= 1_000_000.0 && count > 0 {
                " [THRASHING]"
            } else {
                ""
            };

            writeln!(
                &mut out,
                "{:>16} : {:<8} |{:<36}| {:>5.1}%{}",
                range_str, count, bar, pct, marker
            )
            .unwrap();
        }

        writeln!(&mut out).unwrap();
        out
    }
}
