/* This file is part of Nighthawk Apps (https://nighthawkapps.com)
 *
 * Copyright (C) 2026 Nighthawk Apps
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//! Simple per-peer rate limiter for OMR RPCs (S6).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Sliding-window counter: at most `limit` events per `window` per IP.
pub struct PeerRateLimiter {
    limit: u32,
    window: Duration,
    inner: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

impl PeerRateLimiter {
    pub fn new(limit_per_window: u32, window: Duration) -> Self {
        Self {
            limit: limit_per_window,
            window,
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Returns `true` if the request is allowed (consumes 1 credit).
    pub fn check(&self, peer: IpAddr) -> bool {
        self.check_n(peer, 1)
    }

    /// Consume `n` credits for a multi-key request. Returns `true` if allowed.
    ///
    /// S15: poisoned mutex fails closed (deny).
    pub fn check_n(&self, peer: IpAddr, n: u32) -> bool {
        if self.limit == 0 {
            return true;
        }
        if n == 0 {
            return true;
        }
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            // S15: fail-closed on poisoned mutex
            Err(_) => return false,
        };
        let now = Instant::now();
        // Opportunistic GC: drop stale IP entries when the map grows.
        const GC_THRESHOLD: usize = 256;
        if guard.len() >= GC_THRESHOLD {
            let window = self.window;
            guard.retain(|_, (_, t)| now.duration_since(*t) < window);
        }
        let entry = guard.entry(peer).or_insert((0, now));
        if now.duration_since(entry.1) >= self.window {
            *entry = (n, now);
            return n <= self.limit;
        }
        if entry.0.saturating_add(n) > self.limit {
            return false;
        }
        entry.0 += n;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_n_consumes_multiple_credits() {
        let limiter = PeerRateLimiter::new(5, Duration::from_secs(60));
        let peer: IpAddr = "203.0.113.20".parse().unwrap();
        assert!(limiter.check_n(peer, 3));
        assert!(limiter.check_n(peer, 2));
        assert!(!limiter.check_n(peer, 1));
    }

    #[test]
    fn poisoned_mutex_fails_closed() {
        let peer: IpAddr = "203.0.113.21".parse().unwrap();

        // Poison the mutex, then verify check returns false (fail-closed).
        let limiter = PeerRateLimiter {
            limit: 10,
            window: Duration::from_secs(60),
            inner: Mutex::new(HashMap::new()),
        };
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = limiter.inner.lock().unwrap();
            panic!("poison rate limiter");
        }));
        assert!(limiter.inner.lock().is_err());
        assert!(
            !limiter.check(peer),
            "poisoned mutex must deny (fail-closed)"
        );
        assert!(!limiter.check_n(peer, 2));
    }
}
