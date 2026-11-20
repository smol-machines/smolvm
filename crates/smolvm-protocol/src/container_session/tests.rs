use super::*;

fn identity() -> ExecutionId {
    "a".repeat(32).try_into().unwrap()
}
fn resume() -> Resume {
    Resume {
        execution: identity(),
        output_next: 50,
        input_next: 10,
    }
}
fn snapshot() -> Snapshot {
    Snapshot {
        execution: identity(),
        output_first: 20,
        output_next: 60,
        input_next: 10,
    }
}

#[test]
fn attaching_to_a_restarted_execution_is_rejected_even_with_matching_cursors() {
    let mut other = snapshot();
    other.execution = "b".repeat(32).try_into().unwrap();
    assert_eq!(
        other.reconcile(&resume()),
        Err("container execution changed")
    );
    for invalid in [
        "",
        "web",
        "../execution",
        &"a".repeat(31),
        &"A".repeat(32),
        &"g".repeat(32),
    ] {
        assert!(serde_json::from_value::<ExecutionId>(serde_json::json!(invalid)).is_err());
    }
}

#[test]
fn lost_input_acknowledgement_is_distinct_from_an_uncommitted_record() {
    let host = resume();
    let mut guest = snapshot();
    let retry = guest.reconcile(&host).unwrap();
    assert_eq!(retry.input_next, 10);
    assert!(retry.may_retry_pending_input());
    guest.input_next = 11;
    let acknowledged = guest.reconcile(&host).unwrap();
    assert_eq!(acknowledged.input_next, 11);
    assert_eq!(acknowledged.output, OutputResume::Continuous(50));
    guest.input_next = 12;
    assert!(guest.reconcile(&host).is_err());
}

#[test]
fn retained_output_reports_a_gap_and_checkpoint_rewind_never_replays_later_input() {
    let host = resume();
    let mut guest = snapshot();
    guest.output_first = 55;
    let gap = guest.reconcile(&host).unwrap();
    assert_eq!(
        gap.output,
        OutputResume::Gap {
            requested: 50,
            available: 55
        }
    );
    assert!(gap.may_retry_pending_input());
    guest.output_first = 1;
    guest.output_next = 25;
    let rewind = guest.reconcile(&host).unwrap();
    assert_eq!(
        rewind.output,
        OutputResume::Rewound {
            previous: 50,
            current: 25
        }
    );
    assert!(!rewind.may_retry_pending_input());
    guest = snapshot();
    guest.input_next = 5;
    let input_rewind = guest.reconcile(&host).unwrap();
    assert_eq!(input_rewind.output, OutputResume::Continuous(50));
    assert!(input_rewind.input_rewound);
    assert!(!input_rewind.may_retry_pending_input());
}

#[test]
fn invalid_and_exhausted_cursors_never_wrap_into_a_new_execution() {
    let host = resume();
    for (first, next, input) in [(0, 1, 1), (2, 1, 1), (1, 2, 0)] {
        let mut guest = snapshot();
        guest.output_first = first;
        guest.output_next = next;
        guest.input_next = input;
        assert!(guest.reconcile(&host).is_err());
    }
    for (output_next, input_next) in [(0, 1), (1, 0)] {
        assert!(snapshot()
            .reconcile(&Resume {
                output_next,
                input_next,
                ..resume()
            })
            .is_err());
    }
    let bytes = Input::Data { bytes: vec![1] };
    let cursor = InputCursor {
        committed: Some((u64::MAX, bytes.clone())),
        stdin_closed: false,
    };
    assert_eq!(cursor.next(), None);
    assert!(cursor.check(0, &bytes).is_err());
    assert_eq!(
        cursor.check(u64::MAX, &bytes),
        Ok(InputDisposition::Acknowledge)
    );
}

#[test]
fn repeated_input_is_acknowledged_without_reapplying_and_changed_replays_fail() {
    let mut cursor = InputCursor::default();
    let first = Input::Data {
        bytes: b"one command\n".to_vec(),
    };
    assert_eq!(cursor.check(1, &first), Ok(InputDisposition::Apply));
    // Checking an unqueued frame cannot accidentally acknowledge it.
    assert_eq!(cursor.next(), Some(1));
    cursor.commit(1, first.clone()).unwrap();
    for _ in 0..100 {
        assert_eq!(cursor.check(1, &first), Ok(InputDisposition::Acknowledge));
        cursor.commit(1, first.clone()).unwrap();
        assert_eq!(cursor.next(), Some(2));
    }
    let changed = Input::Data {
        bytes: b"different command\n".to_vec(),
    };
    assert!(cursor.check(1, &changed).is_err());
    assert!(cursor.check(3, &changed).is_err());
    cursor.commit(2, changed).unwrap();
    assert!(cursor.check(1, &first).is_err());
}

#[test]
fn eof_cannot_be_undone_by_reconnection_and_resize_remains_available() {
    let mut cursor = InputCursor::default();
    cursor.commit(1, Input::Eof {}).unwrap();
    assert_eq!(
        cursor.check(1, &Input::Eof {}),
        Ok(InputDisposition::Acknowledge)
    );
    assert!(cursor.check(2, &Input::Data { bytes: vec![] }).is_err());
    assert!(cursor.check(2, &Input::Eof {}).is_err());
    cursor
        .commit(2, Input::Resize { cols: 80, rows: 24 })
        .unwrap();
    assert!(cursor.check(3, &Input::Data { bytes: vec![1] }).is_err());
}

#[test]
fn inputs_are_bounded_and_control_fields_are_strict() {
    let mut cursor = InputCursor::default();
    assert!(cursor
        .commit(
            1,
            Input::Data {
                bytes: vec![1; MAX_INPUT_BYTES + 1]
            }
        )
        .is_err());
    assert_eq!(cursor.next(), Some(1));
    cursor
        .commit(
            1,
            Input::Data {
                bytes: vec![1; MAX_INPUT_BYTES],
            },
        )
        .unwrap();
    assert!(cursor
        .check(2, &Input::Resize { cols: 0, rows: 24 })
        .is_err());
    assert!(serde_json::from_str::<Input>(r#"{"kind":"eof","bytes":"abc"}"#).is_err());
    let value = serde_json::to_value(resume()).unwrap();
    assert_eq!(
        serde_json::from_value::<Resume>(value.clone()).unwrap(),
        resume()
    );
    let mut extra = value;
    extra["other_execution"] = true.into();
    assert!(serde_json::from_value::<Resume>(extra).is_err());
    let input = Input::Data {
        bytes: vec![0, 255, 10],
    };
    let encoded = serde_json::to_string(&input).unwrap();
    assert_eq!(serde_json::from_str::<Input>(&encoded).unwrap(), input);
}
