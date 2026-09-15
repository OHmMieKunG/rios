use rios_simulator::{
    QosScheduler, QueueClassConfig, QueueRejectReason, RateLimit, ScheduleError, SimTime,
};
fn rate(bits: u64, burst: u64) -> RateLimit {
    RateLimit {
        bits_per_second: bits,
        burst_bytes: burst,
    }
}
#[test]
fn priority_precedes_bulk_and_each_class_remains_fifo() {
    let mut q = QosScheduler::new(
        vec![
            QueueClassConfig::default(),
            QueueClassConfig {
                priority: Some(rate(1_000_000, 1000)),
                ..Default::default()
            },
        ],
        10,
        SimTime(0),
    )
    .unwrap();
    for (class, packet) in [(0, 1), (0, 2), (1, 3), (1, 4)] {
        q.enqueue(class, SimTime(0), packet, 100, 0).unwrap();
    }
    let packets: Vec<_> = (0..4)
        .map(|_| q.dequeue_ready(SimTime(0)).unwrap().packet)
        .collect();
    assert_eq!(packets, [3, 4, 1, 2]);
    assert!(q.is_empty());
    assert_eq!(
        q.statistics()
            .map(|(s, _)| s.transmitted_packets)
            .collect::<Vec<_>>(),
        [2, 2]
    );
}
#[test]
fn weighted_byte_service_allocates_one_to_three_under_continuous_backlog() {
    let mut q = QosScheduler::new(
        vec![
            QueueClassConfig::default(),
            QueueClassConfig {
                weight: 3,
                ..Default::default()
            },
        ],
        200,
        SimTime(0),
    )
    .unwrap();
    for sequence in 0..100 {
        for class in 0..2 {
            q.enqueue(class, SimTime(0), (class, sequence), 100, 0)
                .unwrap();
        }
    }
    let mut counts = [0, 0];
    let mut next = [0, 0];
    for _ in 0..80 {
        let sent = q.dequeue_ready(SimTime(0)).unwrap();
        assert_eq!(sent.packet.1, next[sent.class]);
        next[sent.class] += 1;
        counts[sent.class] += sent.bytes;
    }
    assert_eq!(counts, [2000, 6000]);
}
#[test]
fn shaping_waits_exactly_and_does_not_block_another_class() {
    let mut q = QosScheduler::new(
        vec![
            QueueClassConfig {
                shape: Some(rate(8000, 100)),
                ..Default::default()
            },
            QueueClassConfig::default(),
        ],
        10,
        SimTime(0),
    )
    .unwrap();
    q.enqueue(0, SimTime(0), 1, 100, 0).unwrap();
    q.enqueue(0, SimTime(0), 2, 100, 0).unwrap();
    assert_eq!(q.dequeue_ready(SimTime(0)).unwrap().packet, 1);
    assert_eq!(q.next_ready(SimTime(0)).unwrap(), Some(SimTime(100_000)));
    assert!(q.dequeue_ready(SimTime(99_999)).is_none());
    q.enqueue(1, SimTime(99_999), 3, 100, 0).unwrap();
    assert_eq!(q.dequeue_ready(SimTime(99_999)).unwrap().packet, 3);
    assert_eq!(q.dequeue_ready(SimTime(100_000)).unwrap().packet, 2);
    assert_eq!(q.next_ready(SimTime(100_000)).unwrap(), None);
}
#[test]
fn policing_retains_fractional_credit_and_reports_owned_drops() {
    let mut q = QosScheduler::new(
        vec![QueueClassConfig {
            police: Some(rate(1, 1)),
            ..Default::default()
        }],
        10,
        SimTime(0),
    )
    .unwrap();
    q.enqueue(0, SimTime(0), 1, 1, 0).unwrap();
    q.dequeue_ready(SimTime(0));
    for micros in [1, 100, 999, 1000, 7_999_999] {
        let rejected = q.enqueue(0, SimTime(micros), 2, 1, 0).unwrap_err();
        assert_eq!(rejected.reason, QueueRejectReason::Policed);
        assert_eq!(rejected.packet, 2);
    }
    q.enqueue(0, SimTime(8_000_000), 3, 1, 0).unwrap();
    assert_eq!(q.statistics().next().unwrap().0.police_drops, 5);
}
#[test]
fn priority_excess_is_dropped_only_during_congestion() {
    let mut q = QosScheduler::new(
        vec![QueueClassConfig {
            priority: Some(rate(8, 1)),
            ..Default::default()
        }],
        10,
        SimTime(0),
    )
    .unwrap();
    q.enqueue(0, SimTime(0), 1, 1, 0).unwrap();
    assert_eq!(
        q.enqueue(0, SimTime(0), 2, 1, 0).unwrap_err().reason,
        QueueRejectReason::PriorityExceeded
    );
    q.dequeue_ready(SimTime(0));
    // No queued or in-flight traffic: unused link capacity is available above the priority rate.
    q.enqueue(0, SimTime(1), 3, 1, 0).unwrap();
    q.dequeue_ready(SimTime(1));
    assert_eq!(
        q.enqueue(0, SimTime(2), 4, 1, 1).unwrap_err().reason,
        QueueRejectReason::PriorityExceeded
    );
}
#[test]
fn queue_bounds_include_frames_in_flight_and_drain_preserves_ownership() {
    let mut q = QosScheduler::new(vec![QueueClassConfig::default()], 2, SimTime(0)).unwrap();
    q.enqueue(0, SimTime(0), "accepted", 100, 1).unwrap();
    assert_eq!(
        q.enqueue(0, SimTime(0), "full", 100, 1).unwrap_err().reason,
        QueueRejectReason::Full
    );
    assert_eq!(q.len(), 1);
    assert_eq!(q.statistics().next().unwrap().0.queue_drops, 1);
    assert_eq!(q.drain(), ["accepted"]);
    assert!(q.is_empty());
    assert_eq!(
        q.enqueue(3, SimTime(0), "bad class", 100, 0)
            .unwrap_err()
            .reason,
        QueueRejectReason::UnknownClass
    );
}
#[test]
fn invalid_limits_oversized_shape_packets_and_timer_overflow_are_explicit() {
    assert!(QosScheduler::<u8>::new(vec![], 1, SimTime(0)).is_err());
    assert!(
        QosScheduler::<u8>::new(
            vec![QueueClassConfig {
                weight: 0,
                ..Default::default()
            }],
            1,
            SimTime(0)
        )
        .is_err()
    );
    assert!(
        QosScheduler::<u8>::new(
            vec![QueueClassConfig {
                police: Some(rate(0, 1)),
                ..Default::default()
            }],
            1,
            SimTime(0)
        )
        .is_err()
    );
    let mut q = QosScheduler::new(
        vec![QueueClassConfig {
            shape: Some(rate(1, 1)),
            ..Default::default()
        }],
        2,
        SimTime(u64::MAX),
    )
    .unwrap();
    assert_eq!(
        q.enqueue(0, SimTime(u64::MAX), 0, 2, 0).unwrap_err().reason,
        QueueRejectReason::ShapeBurstExceeded
    );
    q.enqueue(0, SimTime(u64::MAX), 1, 1, 0).unwrap();
    q.dequeue_ready(SimTime(u64::MAX));
    q.enqueue(0, SimTime(u64::MAX), 2, 1, 0).unwrap();
    assert_eq!(
        q.next_ready(SimTime(u64::MAX)),
        Err(ScheduleError::Overflow)
    );
}

#[test]
fn equal_weights_share_bytes_even_when_packet_sizes_differ() {
    let mut q = QosScheduler::new(vec![QueueClassConfig::default(); 2], 200, SimTime(0)).unwrap();
    for packet in 0..100 {
        for (class, bytes) in [(0, 100), (1, 300)] {
            q.enqueue(class, SimTime(0), packet, bytes, 0).unwrap();
        }
    }
    let mut bytes = [0, 0];
    for _ in 0..80 {
        let sent = q.dequeue_ready(SimTime(0)).unwrap();
        bytes[sent.class] += sent.bytes;
    }
    assert_eq!(bytes, [6000, 6000]);
}
