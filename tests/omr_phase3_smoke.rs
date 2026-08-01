//! Phase 3: lightweight OMR wire / rate-limit unit tests.
//! Full cross-repo e2e (send clue → digest → decrypt → note) belongs in CI
//! once a shared `darkfi-omr-core` crate lands.

use darkfi_lightwalletd::rate_limit::PeerRateLimiter;
use std::net::IpAddr;
use std::time::Duration;

#[test]
fn omr_rate_limiter_blocks_after_limit() {
    let limiter = PeerRateLimiter::new(3, Duration::from_secs(60));
    let peer: IpAddr = "203.0.113.10".parse().unwrap();
    assert!(limiter.check(peer));
    assert!(limiter.check(peer));
    assert!(limiter.check(peer));
    assert!(!limiter.check(peer));
}

#[test]
fn omr_rate_limiter_disabled_when_zero() {
    let limiter = PeerRateLimiter::new(0, Duration::from_secs(60));
    let peer: IpAddr = "203.0.113.11".parse().unwrap();
    for _ in 0..100 {
        assert!(limiter.check(peer));
    }
}

#[test]
fn omr_rate_limiter_check_n_multi_key() {
    let limiter = PeerRateLimiter::new(4, Duration::from_secs(60));
    let peer: IpAddr = "203.0.113.12".parse().unwrap();
    assert!(limiter.check_n(peer, 2));
    assert!(limiter.check_n(peer, 2));
    assert!(!limiter.check_n(peer, 1));
}
