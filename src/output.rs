use std::io::{self, Write};

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::CertInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatKind {
    Jsonl,
    Table,
    Text,
}

impl FormatKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "jsonl" => Some(Self::Jsonl),
            "table" => Some(Self::Table),
            "text" => Some(Self::Text),
            _ => None,
        }
    }

    pub fn write_results(&self, w: &mut dyn Write, records: &[HostRecord]) -> io::Result<()> {
        match self {
            Self::Jsonl => JsonlFormatter.write_results(w, records),
            Self::Table => TableFormatter {
                wrote_header: false,
            }
            .write_results(w, records),
            Self::Text => TextFormatter.write_results(w, records),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HostRecord {
    pub host: String,
    pub port: u16,
    pub days_until_expiry: Option<i64>,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
    pub subject_cn: Option<String>,
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl HostRecord {
    pub fn success(info: &CertInfo) -> Self {
        Self {
            host: info.host.clone(),
            port: info.port,
            days_until_expiry: Some(info.days_until_expiry),
            not_before: Some(info.not_before),
            not_after: Some(info.not_after),
            subject_cn: Some(info.subject_cn.clone()),
            issuer: Some(info.issuer.clone()),
            error: None,
        }
    }

    pub fn failure(host: &str, port: u16, message: &str) -> Self {
        Self {
            host: host.to_string(),
            port,
            days_until_expiry: None,
            not_before: None,
            not_after: None,
            subject_cn: None,
            issuer: None,
            error: Some(message.to_string()),
        }
    }
}

pub trait Formatter {
    fn write_header(&mut self, w: &mut dyn Write) -> io::Result<()>;
    fn write_one(&mut self, w: &mut dyn Write, record: &HostRecord) -> io::Result<()>;
    fn write_footer(&mut self, w: &mut dyn Write) -> io::Result<()>;

    fn write_results(&mut self, w: &mut dyn Write, records: &[HostRecord]) -> io::Result<()> {
        self.write_header(w)?;
        for record in records {
            self.write_one(w, record)?;
        }
        self.write_footer(w)
    }
}

pub struct JsonlFormatter;

impl Formatter for JsonlFormatter {
    fn write_header(&mut self, _w: &mut dyn Write) -> io::Result<()> {
        Ok(())
    }

    fn write_one(&mut self, w: &mut dyn Write, record: &HostRecord) -> io::Result<()> {
        serde_json::to_writer(&mut *w, record)?;
        w.write_all(b"\n")?;
        Ok(())
    }

    fn write_footer(&mut self, w: &mut dyn Write) -> io::Result<()> {
        w.flush()
    }
}

pub struct TableFormatter {
    wrote_header: bool,
}

impl Formatter for TableFormatter {
    fn write_header(&mut self, w: &mut dyn Write) -> io::Result<()> {
        writeln!(
            w,
            "{:<30} {:>5} {:>8} {:>24} {:>24} {:>20} {:>30}",
            "HOST", "PORT", "DAYS", "NOT_BEFORE", "NOT_AFTER", "SUBJECT_CN", "ISSUER"
        )?;
        self.wrote_header = true;
        Ok(())
    }

    fn write_one(&mut self, w: &mut dyn Write, record: &HostRecord) -> io::Result<()> {
        if !self.wrote_header {
            self.write_header(w)?;
        }
        if let Some(err) = &record.error {
            writeln!(
                w,
                "{:<30} {:>5} {:>8} {:>24} {:>24} {:>20} {:>30}",
                record.host, record.port, "ERR", "-", "-", "-", err
            )?;
            return Ok(());
        }
        writeln!(
            w,
            "{:<30} {:>5} {:>8} {:>24} {:>24} {:>20} {:>30}",
            record.host,
            record.port,
            record.days_until_expiry.unwrap_or(0),
            record
                .not_before
                .map(|d| d.to_rfc3339())
                .unwrap_or_else(|| "-".to_string()),
            record
                .not_after
                .map(|d| d.to_rfc3339())
                .unwrap_or_else(|| "-".to_string()),
            record.subject_cn.as_deref().unwrap_or("-"),
            record.issuer.as_deref().unwrap_or("-"),
        )?;
        Ok(())
    }

    fn write_footer(&mut self, w: &mut dyn Write) -> io::Result<()> {
        w.flush()
    }
}

pub struct TextFormatter;

impl Formatter for TextFormatter {
    fn write_header(&mut self, _w: &mut dyn Write) -> io::Result<()> {
        Ok(())
    }

    fn write_one(&mut self, w: &mut dyn Write, record: &HostRecord) -> io::Result<()> {
        if let Some(err) = &record.error {
            writeln!(w, "{}:{} ERROR: {}", record.host, record.port, err)?;
            return Ok(());
        }
        writeln!(
            w,
            "{}:{} expires in {} days (not_after={}, subject_cn={}, issuer={})",
            record.host,
            record.port,
            record.days_until_expiry.unwrap_or(0),
            record
                .not_after
                .map(|d| d.to_rfc3339())
                .unwrap_or_else(|| "?".to_string()),
            record.subject_cn.as_deref().unwrap_or("?"),
            record.issuer.as_deref().unwrap_or("?"),
        )?;
        Ok(())
    }

    fn write_footer(&mut self, w: &mut dyn Write) -> io::Result<()> {
        w.flush()
    }
}
