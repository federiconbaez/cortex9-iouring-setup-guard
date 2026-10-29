use iouring_setup_guard::flags;
use iouring_setup_guard::{embedded_catalog, try_setup, Decision, Guard};

#[test]
fn measure_50_sqpoll_blocked() {
    let g = Guard::default();
    for _ in 0..50 {
        let r = try_setup(&g, 8, flags::SQPOLL, false).unwrap();
        assert_eq!(r.decision, "deny");
    }
}

#[test]
fn clean_setup_on_box() {
    let g = Guard::default();
    let r = try_setup(&g, 8, 0, true).unwrap();
    assert_eq!(r.decision, "allow");
    assert!(r.fd_or_errno >= 0, "{r:?}");
}

#[test]
fn catalog_size() {
    assert!(embedded_catalog().len() >= 10);
}

#[test]
fn deny_decision_matches() {
    let g = Guard::default();
    assert!(matches!(g.check(flags::NO_MMAP), Decision::Deny { .. }));
}
