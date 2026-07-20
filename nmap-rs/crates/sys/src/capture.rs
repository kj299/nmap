//! Packet capture into the async runtime — the realization of spike **S1**
//! (`SPIKES.md` M4-1). Replaces nmap's `nsock/src/nsock_pcap.c` + the `engine_iocp`
//! poll loop.
//!
//! ## Why a blocking thread, not an `AsyncFd`
//!
//! nmap's pcap handle exposes **no selectable file descriptor** on Windows
//! (`PCAP_CAN_DO_SELECT` is undefined on WIN32; Npcap has no readiness fd), so the
//! usual "register the fd with the reactor" trick is unavailable on the primary
//! target. The spike measured a **dedicated blocking capture thread forwarding frames
//! into a `tokio::mpsc` channel** at ~60 µs send→deliver latency with 0 idle CPU —
//! and, crucially, it needs no selectable fd, so the exact same design ports to Npcap.
//!
//! ## Shape (portable seam + audited-real / mock split, per Option C)
//!
//! * [`PacketSource`] is the seam: a **blocking** "give me the next frame" call. The
//!   async plumbing here is OS-agnostic and holds **0 `unsafe`**.
//! * [`AsyncCapture`] spawns the capture thread and hands back an async receiver plus
//!   clean shutdown. This is what CI builds and tests (against a mock source).
//! * Under the off-by-default `pcap` feature, [`pcap_source`] provides a live
//!   libpcap/Npcap-backed `PacketSource`, validated on a privileged host.
//!
//! **Contract for a `PacketSource`:** `next_frame` MUST return within a bounded time
//! (a read timeout, `Ok(None)` on expiry) rather than block forever, so the thread can
//! observe a stop request promptly. The pcap backend sets libpcap's read timeout.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use tokio::sync::mpsc;

#[cfg(feature = "pcap")]
pub mod pcap_source;

/// A blocking source of captured link-layer frames.
///
/// Implementations must be responsive to shutdown: `next_frame` should use a bounded
/// read timeout and return `Ok(None)` on expiry rather than blocking indefinitely.
pub trait PacketSource: Send + 'static {
    /// Block (up to the source's read timeout) for the next frame.
    ///
    /// * `Ok(Some(bytes))` — a captured frame.
    /// * `Ok(None)` — the read timed out; no frame this round (the caller loops).
    /// * `Err(_)` — a fatal capture error; the capture thread stops.
    ///
    /// # Errors
    /// Propagates a fatal error from the underlying capture handle.
    fn next_frame(&mut self) -> io::Result<Option<Vec<u8>>>;
}

/// One captured frame delivered to the async side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedFrame {
    /// Raw link-layer bytes as captured (subject to the capture snap length).
    pub data: Vec<u8>,
}

/// A running capture: a blocking thread pumping [`CapturedFrame`]s into a bounded
/// channel that the async side drains via [`AsyncCapture::recv`]. Dropping (or
/// [`AsyncCapture::stop`]) signals the thread and joins it.
pub struct AsyncCapture {
    rx: mpsc::Receiver<CapturedFrame>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl AsyncCapture {
    /// Spawn the capture thread over `source`, buffering up to `capacity` frames of
    /// backpressure. The thread blocks in `source.next_frame()` and forwards frames;
    /// it exits when the source errors, the receiver is dropped, or a stop is signalled.
    #[must_use]
    pub fn spawn<S: PacketSource>(mut source: S, capacity: usize) -> AsyncCapture {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let join = std::thread::Builder::new()
            .name("nmap-capture".to_string())
            .spawn(move || {
                while !stop_thread.load(Ordering::Relaxed) {
                    match source.next_frame() {
                        // A frame: forward it. `blocking_send` applies backpressure;
                        // if the receiver is gone it errors and we stop.
                        Ok(Some(data)) => {
                            if tx.blocking_send(CapturedFrame { data }).is_err() {
                                break;
                            }
                        }
                        // Read timeout: loop back to re-check the stop flag.
                        Ok(None) => {}
                        // Fatal capture error: end the capture.
                        Err(_) => break,
                    }
                }
            })
            .expect("spawn capture thread");
        AsyncCapture {
            rx,
            stop,
            join: Some(join),
        }
    }

    /// Await the next captured frame. Returns `None` once the capture has stopped and
    /// the channel is drained.
    pub async fn recv(&mut self) -> Option<CapturedFrame> {
        self.rx.recv().await
    }

    /// Signal the capture thread to stop. Delivery of already-queued frames still
    /// works until the channel drains. Idempotent; also done on drop.
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Wake a thread blocked in `blocking_send` by refusing further sends.
        self.rx.close();
    }
}

impl Drop for AsyncCapture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.rx.close();
        if let Some(handle) = self.join.take() {
            // The source's bounded read timeout guarantees this join is prompt.
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// A scripted source: yields each item of `script` in turn (`None` models a read
    /// timeout), then behaves per `after`: `Idle` returns `Ok(None)` forever, `End`
    /// returns a fatal error so the thread exits and the channel closes.
    struct MockSource {
        script: std::vec::IntoIter<Option<Vec<u8>>>,
        after_end: bool,
        polls: Arc<AtomicUsize>,
    }

    impl MockSource {
        fn new(script: Vec<Option<Vec<u8>>>, after_end: bool, polls: Arc<AtomicUsize>) -> Self {
            MockSource {
                script: script.into_iter(),
                after_end,
                polls,
            }
        }
    }

    impl PacketSource for MockSource {
        fn next_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
            self.polls.fetch_add(1, Ordering::Relaxed);
            match self.script.next() {
                Some(item) => Ok(item),
                None if self.after_end => Err(io::Error::other("end")),
                None => {
                    // Idle: sleep a touch so we don't spin, then report a timeout.
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    Ok(None)
                }
            }
        }
    }

    fn frame(b: u8) -> Option<Vec<u8>> {
        Some(vec![b; 4])
    }

    #[tokio::test]
    async fn delivers_frames_in_order_skipping_timeouts() {
        let polls = Arc::new(AtomicUsize::new(0));
        let src = MockSource::new(
            vec![frame(1), None, frame(2), frame(3)],
            true, // end after script -> channel closes
            Arc::clone(&polls),
        );
        let mut cap = AsyncCapture::spawn(src, 16);

        assert_eq!(cap.recv().await, Some(CapturedFrame { data: vec![1; 4] }));
        assert_eq!(cap.recv().await, Some(CapturedFrame { data: vec![2; 4] }));
        assert_eq!(cap.recv().await, Some(CapturedFrame { data: vec![3; 4] }));
        // Source errored after the script -> capture ends -> channel closes.
        assert_eq!(cap.recv().await, None);
        assert!(polls.load(Ordering::Relaxed) >= 4);
    }

    #[tokio::test]
    async fn backpressure_preserves_order_with_small_capacity() {
        // 50 frames through a capacity-1 channel with a slow reader: none lost, in order.
        let polls = Arc::new(AtomicUsize::new(0));
        let script: Vec<Option<Vec<u8>>> = (0..50u8).map(|i| Some(vec![i])).collect();
        let src = MockSource::new(script, true, Arc::clone(&polls));
        let mut cap = AsyncCapture::spawn(src, 1);

        for i in 0..50u8 {
            let f = cap.recv().await.expect("frame present");
            assert_eq!(f.data, vec![i]);
            // Reader is slower than the source can produce -> exercises backpressure.
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        assert_eq!(cap.recv().await, None);
    }

    #[tokio::test]
    async fn stop_ends_the_stream_and_joins_cleanly() {
        // An idle source (never ends on its own); stop() must terminate it.
        let polls = Arc::new(AtomicUsize::new(0));
        let src = MockSource::new(vec![frame(9)], false, Arc::clone(&polls));
        let mut cap = AsyncCapture::spawn(src, 8);

        assert_eq!(cap.recv().await, Some(CapturedFrame { data: vec![9; 4] }));
        cap.stop();
        // After stop + drain, the stream ends.
        assert_eq!(cap.recv().await, None);
        // Dropping joins the thread; if it hung, the test would hang.
        drop(cap);
    }

    #[tokio::test]
    async fn drop_without_draining_does_not_hang() {
        // Spawn over an idle source producing frames, then drop immediately without
        // recv — Drop must signal + join without deadlocking on a full channel.
        let polls = Arc::new(AtomicUsize::new(0));
        let script: Vec<Option<Vec<u8>>> = (0..100u8).map(|i| Some(vec![i])).collect();
        let src = MockSource::new(script, false, polls);
        let cap = AsyncCapture::spawn(src, 2);
        drop(cap); // must return promptly
    }
}
