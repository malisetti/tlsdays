#![forbid(unsafe_code)]

use std::io::{self, BufRead, IsTerminal, Write};
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use futures::stream::{self, StreamExt};
use tlsdays::{
    check_host, FormatKind, Formatter, HostRecord, HostTarget, TlsdaysError,
};

#[derive(Debug, Parser)]
#[command(
    name = "tlsdays",
    version,
    about = "Report days until TLS certificates expire across many hostnames in parallel"
)]
struct Cli {
    /// Output format: jsonl, table, or text
    #[arg(long, value_name = "FORMAT", default_value = "text")]
    format: String,

    /// Per-host connect/handshake timeout in milliseconds
    #[arg(long, value_name = "MS", default_value_t = 10_000)]
    timeout_ms: u64,

    /// Maximum concurrent host checks
    #[arg(long, value_name = "N", default_value_t = 32)]
    concurrent: usize,

    /// Default TCP port when hosts omit an explicit port
    #[arg(long, value_name = "PORT", default_value_t = 443)]
    port: u16,

    /// Exit with code 2 when any host fails (when disabled, failures are reported but may not force exit 2)
    #[arg(long)]
    strict_fail: bool,

    /// Hostnames to check (host or host:port). If omitted, reads stdin (one host per line).
    hosts: Vec<String>,
}

fn parse_host_entry(entry: &str, default_port: u16) -> Result<HostTarget, TlsdaysError> {
    let entry = entry.trim();
    if entry.is_empty() {
        return Err(TlsdaysError::Argument("empty host entry".to_string()));
    }

    if entry.starts_with('[') {
        let end = entry
            .find(']')
            .ok_or_else(|| TlsdaysError::Argument(format!("invalid bracketed host: {entry}")))?;
        let host = entry[1..end].to_string();
        let port = if let Some(rest) = entry.get(end + 1..) {
            if let Some(port_str) = rest.strip_prefix(':') {
                port_str
                    .parse()
                    .map_err(|_| TlsdaysError::Argument(format!("invalid port in {entry}")))?
            } else if rest.is_empty() {
                default_port
            } else {
                return Err(TlsdaysError::Argument(format!("invalid host spec: {entry}")));
            }
        } else {
            default_port
        };
        return Ok(HostTarget { host, port });
    }

    let colon_count = entry.matches(':').count();
    if colon_count > 1 {
        return Ok(HostTarget {
            host: entry.to_string(),
            port: default_port,
        });
    }
    if let Some((host, port_str)) = entry.rsplit_once(':') {
        if !host.is_empty() {
            if let Ok(port) = port_str.parse::<u16>() {
                return Ok(HostTarget {
                    host: host.to_string(),
                    port,
                });
            }
        }
    }

    Ok(HostTarget {
        host: entry.to_string(),
        port: default_port,
    })
}

fn collect_hosts(cli: &Cli) -> Result<Vec<HostTarget>, TlsdaysError> {
    let mut targets = Vec::new();

    for arg in &cli.hosts {
        targets.push(parse_host_entry(arg, cli.port)?);
    }

    let stdin_has_data = !io::stdin().is_terminal();
    if cli.hosts.is_empty() || stdin_has_data {
        let stdin = io::stdin();
        let lines = stdin.lock().lines();
        for line in lines {
            let line = line.map_err(|e| TlsdaysError::Argument(format!("stdin read error: {e}")))?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            targets.push(parse_host_entry(trimmed, cli.port)?);
        }
    }

    if targets.is_empty() {
        return Err(TlsdaysError::Argument(
            "no hosts provided: pass HOST arguments or pipe hosts on stdin".to_string(),
        ));
    }

    Ok(targets)
}

fn exit_code(records: &[HostRecord], strict_fail: bool) -> u8 {
    let mut any_failure = false;
    let mut min_days: Option<i64> = None;
    let mut any_success = false;

    for record in records {
        if record.error.is_some() {
            any_failure = true;
            continue;
        }
        any_success = true;
        if let Some(days) = record.days_until_expiry {
            min_days = Some(min_days.map_or(days, |m| m.min(days)));
        }
    }

    if any_failure && strict_fail {
        return 2;
    }

    if !any_success {
        return if any_failure { 2 } else { 0 };
    }

    match min_days {
        Some(days) if days < 7 => 1,
        _ => 0,
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            e.print().expect("stderr");
            return ExitCode::from(2);
        }
    };

    let format = match FormatKind::parse(&cli.format) {
        Some(f) => f,
        None => {
            eprintln!("invalid --format: expected jsonl, table, or text");
            return ExitCode::from(2);
        }
    };

    let hosts = match collect_hosts(&cli) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };

    let timeout = Duration::from_millis(cli.timeout_ms);
    let concurrent = cli.concurrent.max(1);

    let results: Vec<HostRecord> = stream::iter(hosts)
        .map(|target| {
            let timeout = timeout;
            async move {
                match check_host(&target.host, target.port, timeout).await {
                    Ok(info) => HostRecord::success(&info),
                    Err(e) => HostRecord::failure(&target.host, target.port, &e.to_string()),
                }
            }
        })
        .buffer_unordered(concurrent)
        .collect()
        .await;

    let stdout = io::stdout();
    let mut handle = stdout.lock();
    let mut formatter = format.formatter(Box::new(&mut handle));
    if let Err(e) = formatter.write_header() {
        eprintln!("output error: {e}");
        return ExitCode::from(2);
    }
    for record in &results {
        if let Err(e) = formatter.write_one(record) {
            eprintln!("output error: {e}");
            return ExitCode::from(2);
        }
    }
    if let Err(e) = formatter.write_footer() {
        eprintln!("output error: {e}");
        return ExitCode::from(2);
    }

    let code = exit_code(&results, cli.strict_fail);
    ExitCode::from(code)
}
