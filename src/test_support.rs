//! Helpers shared by unit tests.

/// Run the calling test in a fresh copy of the test binary; evaluates to
/// `true` in that copy (run the test body) and `false` in the original, which
/// has already checked that the copy passed and must return at once.
///
/// For a test that takes a non-blocking file lock (`flock` with `LOCK_NB`,
/// `File::try_lock`), directly or through the code under test, and needs it
/// free right after an earlier holder let go. Every such test in this crate
/// uses it; a new one must too. Every test shares one process, and when
/// another test spawns a child, the child holds a copy of every open
/// descriptor until it execs, so a lock released here can still be held by
/// that copy for a moment and the non-blocking attempt fails.
macro_rules! in_own_process {
    () => {{
        fn here() {}
        $crate::test_support::run_in_own_process(std::any::type_name_of_val(&here))
    }};
}
pub(crate) use in_own_process;

#[doc(hidden)]
pub(crate) fn run_in_own_process(here: &str) -> bool {
    // "smolvm::module::tests::name::here" -> "module::tests::name"
    let test = here
        .strip_suffix("::here")
        .and_then(|path| path.split_once("::"))
        .map(|(_, path)| path)
        .expect("called from a test function");
    if std::env::var("SMOLVM_TEST_OWN_PROCESS").as_deref() == Ok(test) {
        return true;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env("SMOLVM_TEST_OWN_PROCESS", test)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "{test} in its own process:\n{stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    false
}
