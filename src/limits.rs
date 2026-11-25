//! Keeping strangers from using up the server. Anyone who can reach the port can
//! open connections without a key, so how many there are and how long they may
//! say nothing is bounded.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Bounds on HTTPS connections. Live-update sockets leave these bounds once they
/// are accepted (they need a device token, and each vault has its own cap).
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Connections at once, from everyone.
    pub total: usize,
    /// Connections at once from one address. A household behind one address
    /// (or Docker's proxy) has at most a few dozen devices.
    pub per_address: usize,
    /// For the TLS handshake.
    pub handshake: Duration,
    /// For a connection to send its first request, and for each request's headers.
    pub first_request: Duration,
    /// For an open connection with no request in progress.
    pub idle: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            total: 512,
            per_address: 64,
            handshake: Duration::from_secs(20),
            first_request: Duration::from_secs(20),
            idle: Duration::from_secs(120),
        }
    }
}

#[derive(Default)]
struct Counts {
    total: usize,
    by_address: HashMap<IpAddr, usize>,
}

/// Who is connected right now.
#[derive(Clone)]
pub struct Gate {
    limits: Limits,
    counts: Arc<Mutex<Counts>>,
}

/// A place taken by one connection; dropping it frees the place.
pub struct Place {
    address: IpAddr,
    counts: Arc<Mutex<Counts>>,
}

impl Gate {
    pub fn new(limits: Limits) -> Gate {
        Gate {
            limits,
            counts: Arc::default(),
        }
    }

    /// A place for a connection from `address`, or None when there is no room.
    pub fn enter(&self, address: IpAddr) -> Option<Place> {
        let mut c = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        let here = c.by_address.get(&address).copied().unwrap_or(0);
        if c.total >= self.limits.total || here >= self.limits.per_address {
            return None;
        }
        c.total += 1;
        c.by_address.insert(address, here + 1);
        Some(Place {
            address,
            counts: self.counts.clone(),
        })
    }
}

impl Drop for Place {
    fn drop(&mut self) {
        let mut c = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        c.total = c.total.saturating_sub(1);
        if let Some(n) = c.by_address.get_mut(&self.address) {
            *n -= 1;
            if *n == 0 {
                c.by_address.remove(&self.address);
            }
        }
    }
}

#[derive(Debug)]
struct State {
    in_progress: usize,
    served: bool,
    since: Instant,
}

/// What one connection is doing, to tell when it has been quiet too long.
#[derive(Clone, Debug)]
pub struct Activity(Arc<Mutex<State>>);

impl Default for Activity {
    fn default() -> Self {
        Activity(Arc::new(Mutex::new(State {
            in_progress: 0,
            served: false,
            since: Instant::now(),
        })))
    }
}

/// A request being answered; dropping it (done or abandoned) ends it.
pub struct Busy(Activity);

impl Activity {
    pub fn request(&self) -> Busy {
        let mut s = self.0.lock().unwrap_or_else(|e| e.into_inner());
        s.in_progress += 1;
        s.served = true;
        Busy(self.clone())
    }

    /// True when nothing is being answered and the quiet has lasted too long.
    pub fn expired(&self, limits: &Limits) -> bool {
        let s = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let allowed = if s.served {
            limits.idle
        } else {
            limits.first_request
        };
        s.in_progress == 0 && s.since.elapsed() >= allowed
    }
}

impl Drop for Busy {
    fn drop(&mut self) {
        let mut s = self.0.0.lock().unwrap_or_else(|e| e.into_inner());
        s.in_progress = s.in_progress.saturating_sub(1);
        s.since = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, n])
    }

    #[test]
    fn places_are_limited_per_address_and_in_total_and_come_back() {
        let g = Gate::new(Limits {
            total: 3,
            per_address: 2,
            ..Limits::default()
        });
        let a = g.enter(ip(1)).unwrap();
        let _b = g.enter(ip(1)).unwrap();
        assert!(g.enter(ip(1)).is_none(), "one address is full");
        let _c = g.enter(ip(2)).unwrap();
        assert!(g.enter(ip(3)).is_none(), "the server is full");
        drop(a);
        assert!(g.enter(ip(3)).is_some(), "a freed place is used again");
        assert!(g.counts.lock().unwrap().by_address.len() <= 3);
    }

    #[test]
    fn silence_expires_but_work_in_progress_does_not() {
        let limits = Limits {
            first_request: Duration::ZERO,
            idle: Duration::from_secs(3600),
            ..Limits::default()
        };
        let a = Activity::default();
        assert!(a.expired(&limits), "never asked for anything");
        let busy = a.request();
        assert!(!a.expired(&limits), "being answered");
        drop(busy);
        assert!(!a.expired(&limits), "now the longer idle time applies");
        let strict = Limits {
            idle: Duration::ZERO,
            ..limits
        };
        assert!(a.expired(&strict));
    }
}
