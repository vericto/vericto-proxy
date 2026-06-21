//! Métricas del proxy: contadores de decisiones y percentiles de latencia.
//!
//! Latencia objetivo: <2ms p99 en el path de parsing + evaluación.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// Número máximo de muestras de latencia retenidas para el cálculo de percentiles.
const MAX_SAMPLES: usize = 4096;

#[derive(Default)]
pub struct Metrics {
    total: AtomicU64,
    allowed: AtomicU64,
    blocked: AtomicU64,
    parse_errors: AtomicU64,
    /// Muestras de latencia en microsegundos (ventana deslizante).
    latencies_us: Mutex<Vec<u64>>,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_allowed(&self, latency_us: u64) {
        self.total.fetch_add(1, Ordering::Relaxed);
        self.allowed.fetch_add(1, Ordering::Relaxed);
        self.record_latency(latency_us);
    }

    pub fn record_blocked(&self, latency_us: u64) {
        self.total.fetch_add(1, Ordering::Relaxed);
        self.blocked.fetch_add(1, Ordering::Relaxed);
        self.record_latency(latency_us);
    }

    pub fn record_parse_error(&self, latency_us: u64) {
        self.total.fetch_add(1, Ordering::Relaxed);
        self.parse_errors.fetch_add(1, Ordering::Relaxed);
        self.record_latency(latency_us);
    }

    fn record_latency(&self, latency_us: u64) {
        if let Ok(mut samples) = self.latencies_us.lock() {
            if samples.len() >= MAX_SAMPLES {
                samples.remove(0);
            }
            samples.push(latency_us);
        }
    }

    /// Devuelve un snapshot de las métricas para el endpoint `/metrics`.
    pub fn snapshot(&self) -> MetricsSnapshot {
        let (p50_us, p99_us) = self.percentiles();
        MetricsSnapshot {
            total: self.total.load(Ordering::Relaxed),
            allowed: self.allowed.load(Ordering::Relaxed),
            blocked: self.blocked.load(Ordering::Relaxed),
            parse_errors: self.parse_errors.load(Ordering::Relaxed),
            p50_ms: p50_us as f64 / 1000.0,
            p99_ms: p99_us as f64 / 1000.0,
        }
    }

    fn percentiles(&self) -> (u64, u64) {
        let mut samples = match self.latencies_us.lock() {
            Ok(s) => s.clone(),
            Err(_) => return (0, 0),
        };
        if samples.is_empty() {
            return (0, 0);
        }
        samples.sort_unstable();
        let p50_idx = (samples.len() as f64 * 0.50) as usize;
        let p99_idx = (samples.len() as f64 * 0.99) as usize;
        let clamp = |i: usize| samples[i.min(samples.len() - 1)];
        (clamp(p50_idx), clamp(p99_idx))
    }
}

#[derive(Debug, serde::Serialize)]
pub struct MetricsSnapshot {
    pub total: u64,
    pub allowed: u64,
    pub blocked: u64,
    pub parse_errors: u64,
    pub p50_ms: f64,
    pub p99_ms: f64,
}
