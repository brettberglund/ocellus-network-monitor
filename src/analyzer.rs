//! IDS analysis stage: drains the ring buffer in batches, scores each packet via
//! [`IdsEngine`], and forwards the result to the gRPC sender over an mpsc channel.

use std::sync::Arc;

use rayon::ThreadPoolBuilder;
use tokio::sync::mpsc;
use tracing::warn;

use crate::ids::IdsEngine;
use crate::raw_packet::RawPacket;
use crate::ring_buffer::RingBuffer;

/// Drain the ring buffer in a rayon thread pool, score each packet with the IDS engine,
/// and forward scored packets to the gRPC mpsc channel.
pub fn start_analysis(
    buffer: RingBuffer<RawPacket>,
    engine: Arc<IdsEngine>,
    grpc_tx: mpsc::Sender<RawPacket>,
) {
    let pool = ThreadPoolBuilder::new()
        .num_threads(4)
        .thread_name(|i| format!("ids-worker-{}", i))
        .build()
        .expect("failed to build IDS thread pool");

    loop {
        let batch = buffer.drain_batch(64);

        if batch.is_empty() {
            match buffer.pop_blocking() {
                Some(pkt) => {
                    let scored = score_one(pkt, &engine);
                    forward(&grpc_tx, scored);
                }
                None => break, // ring buffer closed — analyzer exits
            }
            continue;
        }

        // Score the batch in parallel; collect results in order.
        let scored_batch: Vec<RawPacket> = pool.install(|| {
            use rayon::prelude::*;
            batch
                .into_par_iter()
                .map(|pkt| score_one(pkt, &engine))
                .collect()
        });

        for pkt in scored_batch {
            forward(&grpc_tx, pkt);
        }
    }
}

fn score_one(mut pkt: RawPacket, engine: &IdsEngine) -> RawPacket {
    let result = engine.analyze(&pkt);
    pkt.ids_score = result.total_score;
    pkt.ids_flag = result.flag_reason;
    pkt
}

fn forward(tx: &mpsc::Sender<RawPacket>, pkt: RawPacket) {
    if tx.try_send(pkt).is_err() {
        warn!("gRPC mpsc channel full or closed — dropping scored packet");
    }
}
