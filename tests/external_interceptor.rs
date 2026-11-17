use std::process::Command;

#[test]
fn interceptor_token_errors_and_help_do_not_expose_environment_values() {
    let args = [
        "machine",
        "start",
        "--name",
        "interceptor-config-test",
        "--egress-interceptor",
        "127.0.0.1:43123",
    ];
    let zero_token = "0".repeat(64);
    for token in [
        None,
        Some("invalid-interceptor-secret"),
        Some("abcd"),
        Some(zero_token.as_str()),
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_smolvm"));
        command.args(args).env_remove("SMOLVM_INTERCEPTOR_TOKEN");
        if let Some(token) = token {
            command.env("SMOLVM_INTERCEPTOR_TOKEN", token);
        }
        let result = command.output().unwrap();
        let stderr = String::from_utf8(result.stderr).unwrap();
        assert!(!result.status.success());
        assert!(stderr.contains("SMOLVM_INTERCEPTOR_TOKEN"), "{stderr}");
        assert!(stderr.contains("64"), "{stderr}");
        if let Some(token) = token {
            assert!(!stderr.contains(token), "token leaked in error");
        }
    }
    let token = "ab".repeat(32);
    let result = Command::new(env!("CARGO_BIN_EXE_smolvm"))
        .args(["machine", "start", "--help"])
        .env("SMOLVM_INTERCEPTOR_TOKEN", &token)
        .output()
        .unwrap();
    assert!(result.status.success());
    assert!(!String::from_utf8(result.stdout).unwrap().contains(&token));
}
