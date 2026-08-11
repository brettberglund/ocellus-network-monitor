//! Thread-safe bounded ring buffer used between the capture thread and the IDS analyzer.
//!
//! When the buffer is full, [`RingBuffer::push`] drops the oldest entry to make room,
//! ensuring the capture thread never blocks on a slow consumer.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};

/// Shared-handle ring buffer backed by a [`VecDeque`] and a condvar for blocking pops.
///
/// Clone the handle with [`RingBuffer::clone_handle`] to share across threads; all clones
/// refer to the same underlying buffer.
pub struct RingBuffer<T> {
    inner: Arc<(Mutex<RingInner<T>>, Condvar)>,
}

struct RingInner<T> {
    buf: VecDeque<T>,
    cap: usize,
    dropped: u64,
    closed: bool,
}

impl<T> RingBuffer<T> {
    pub fn new(cap: usize) -> Self {
        Self {
            inner: Arc::new((
                Mutex::new(RingInner {
                    buf: VecDeque::with_capacity(cap),
                    cap,
                    dropped: 0,
                    closed: false,
                }),
                Condvar::new(),
            )),
        }
    }

    /// Return a second handle to the same buffer (cheap `Arc` clone).
    pub fn clone_handle(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Push packet, if full drop oldest
    /// Returns num packets dropped
    pub fn push(&self, item: T) -> u64 {
        let (lock, cvar) = &*self.inner;
        let mut inner = lock.lock().unwrap();

        if inner.buf.len() == inner.cap {
            inner.buf.pop_front();
            inner.dropped += 1;
        }

        inner.buf.push_back(item);
        cvar.notify_one(); // wake analyzer
        inner.dropped
    }

    /// Block until packet available
    pub fn pop_blocking(&self) -> Option<T> {
        let (lock, cvar) = &*self.inner;
        let mut inner = lock.lock().unwrap();

        loop {
            if let Some(item) = inner.buf.pop_front() {
                return Some(item);
            }
            if inner.closed {
                return None;
            }
            inner = cvar.wait(inner).unwrap();
        }
    }

    /// Non blocking pop
    #[allow(dead_code)]
    pub fn try_pop(&self) -> Option<T> {
        let (lock, _) = &*self.inner;
        lock.lock().unwrap().buf.pop_front()
    }

    /// Remove up to `max` items without blocking; returns an empty vec if the buffer is empty.
    pub fn drain_batch(&self, max: usize) -> Vec<T> {
        let (lock, _) = &*self.inner;
        let mut inner = lock.lock().unwrap();
        let count = max.min(inner.buf.len());
        inner.buf.drain(..count).collect()
    }

    /// Signal consumers to drain and exit; unblocks all waiting [`RingBuffer::pop_blocking`] callers.
    #[allow(dead_code)]
    pub fn close(&self) {
        let (lock, cvar) = &*self.inner;
        lock.lock().unwrap().closed = true;
        cvar.notify_all();
    }

    /// Return `(current_len, total_dropped)` for diagnostics.
    #[allow(dead_code)]
    pub fn stats(&self) -> (usize, u64) {
        let (lock, _) = &*self.inner;
        let inner = lock.lock().unwrap();
        (inner.buf.len(), inner.dropped)
    }
}
