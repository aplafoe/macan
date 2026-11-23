use anyhow::{Context, Result, ensure};

pub struct TimingLimits {
    pub clock: u32,
    pub tseg1_min: u32,
    pub tseg1_max: u32,
    pub tseg2_min: u32,
    pub tseg2_max: u32,
    pub sjw_max: u32,
    pub brp_min: u32,
    pub brp_max: u32,
    pub brp_inc: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Timing {
    pub bitrate: u32,
    pub sample_point: u32,
    pub fields: [u32; 5],
}

impl TimingLimits {
    pub fn calculate(&self, bitrate: u32) -> Result<Timing> {
        ensure!((1..=1_000_000).contains(&bitrate), "classic CAN bitrate must be in 1..=1000000");
        ensure!(
            self.clock > 0
                && self.sjw_max > 0
                && self.brp_inc > 0
                && 0 < self.brp_min
                && self.brp_min <= self.brp_max
                && self.brp_max <= 65536
                && 0 < self.tseg1_min
                && self.tseg1_min <= self.tseg1_max
                && self.tseg1_max <= 1024
                && 0 < self.tseg2_min
                && self.tseg2_min <= self.tseg2_max
                && self.tseg2_max <= 1024,
            "adapter reported invalid bit timing limits"
        );

        let sample_point = match bitrate {
            0..=500_000 => 875,
            500_001..=800_000 => 800,
            _ => 750,
        };
        let clock = u64::from(self.clock);
        let inc = u64::from(self.brp_inc);
        let mut best = None;
        let mut best_score = (u128::MAX, u32::MAX);

        let min_quanta = 1 + self.tseg1_min + self.tseg2_min;
        let max_quanta = 1 + self.tseg1_max + self.tseg2_max;
        for quanta in (min_quanta..=max_quanta).rev() {
            let scale = u64::from(bitrate) * u64::from(quanta) * inc;
            let min_tseg2 = self.tseg2_min.max((quanta - 1).saturating_sub(self.tseg1_max));
            let max_tseg2 = self.tseg2_max.min(quanta - 1 - self.tseg1_min);
            let tseg2 = ((quanta * (1000 - sample_point) + 500) / 1000).clamp(min_tseg2, max_tseg2);
            let actual_sample = (quanta - tseg2) * 1000 / quanta;

            for steps in [clock / scale, clock.div_ceil(scale)] {
                let brp = steps * inc;
                if !(u64::from(self.brp_min)..=u64::from(self.brp_max)).contains(&brp) {
                    continue;
                }
                let desired_clock = steps * scale;
                let error_ppm = u128::from(clock.abs_diff(desired_clock)) * 1_000_000 / u128::from(desired_clock);
                let score = (error_ppm, actual_sample.abs_diff(sample_point));
                if score < best_score {
                    best_score = score;
                    let tseg1 = quanta - 1 - tseg2;
                    let prop_seg = tseg1 / 2;
                    let phase_seg1 = tseg1 - prop_seg;
                    let sjw = phase_seg1.min((tseg2 / 2).max(1)).min(self.sjw_max);
                    best = Some(Timing {
                        bitrate: (clock / (brp * u64::from(quanta))) as u32,
                        sample_point: actual_sample,
                        fields: [prop_seg, phase_seg1, tseg2, sjw, brp as u32],
                    });
                }
            }
        }

        best.filter(|_| best_score.0 <= 5000).context("adapter cannot achieve the requested bitrate within 0.5%")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canable2_at_250_kbit() {
        let limits = TimingLimits {
            clock: 170_000_000,
            tseg1_min: 2,
            tseg1_max: 256,
            tseg2_min: 2,
            tseg2_max: 128,
            sjw_max: 128,
            brp_min: 1,
            brp_max: 512,
            brp_inc: 1,
        };
        let timing = limits.calculate(250_000).unwrap();
        assert_eq!(timing.bitrate, 250_000);
        assert_eq!(timing.sample_point, 875);
        assert_eq!(timing.fields, [59, 59, 17, 8, 5]);
        assert!(limits.calculate(1).is_err());
    }
}
