use assert_cmd::Command;
use predicates::prelude::*;

fn tlsdays() -> Command {
    Command::cargo_bin("tlsdays").unwrap()
}

#[test]
fn missing_hosts_exits_2() {
    tlsdays()
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("no hosts provided"));
}

#[test]
fn invalid_format_exits_2() {
    tlsdays()
        .args(["--format", "xml", "example.com"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("invalid --format"));
}

#[test]
fn help_succeeds() {
    tlsdays().arg("--help").assert().success();
}

#[cfg(feature = "live-tests")]
mod live {
    use super::*;

    #[test]
    fn github_jsonl_exit_0_or_1() {
        tlsdays()
            .args(["--format", "jsonl", "github.com"])
            .assert()
            .success()
            .stdout(predicate::str::contains("github.com"))
            .stdout(predicate::str::contains("days_until_expiry"));
    }

    #[test]
    fn expired_badssl_strict_fail_exit_2() {
        tlsdays()
            .args(["--strict-fail", "expired.badssl.com"])
            .assert()
            .failure()
            .code(2);
    }

    #[test]
    fn table_format_smoke() {
        tlsdays()
            .args(["--format", "table", "github.com"])
            .assert()
            .success()
            .stdout(predicate::str::contains("HOST"));
    }

    #[test]
    fn stdin_host() {
        tlsdays().write_stdin("github.com\n").assert().success();
    }
}

#[test]
fn version_prints() {
    tlsdays()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("0.1.0"));
}
