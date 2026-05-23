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

    pub fn formatter(self, w: Box<dyn Write + Send>) -> Box<dyn Formatter + Send> {
        match self {
            Self::Jsonl => Box::new(JsonlFormatter::new(w)),
            Self::Table => Box::new(TableFormatter::new(w)),
            Self::Text => Box::new(TextFormatter::new(w)),
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
    fn write_header(&mut self) -> io::Result<()>;
    fn write_one(&mut self, record: &HostRecord) -> io::Result<()>;
    fn write_footer(&mut self) -> io::Result<()>;
}

pub struct JsonlFormatter {
    writer: Box<dyn Write + Send>,
}

impl JsonlFormatter {
    pub fn new(writer: Box<dyn Write + Send>) -> Self {
        Self { writer }
    }
}

impl Formatter for JsonlFormatter {
    fn write_header(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn write_one(&mut self, record: &HostRecord) -> io::Result<()> {
        serde_json::to_writer(&mut self.writer, record)?;
        self.writer.write_all(b"\n")?;
        Ok(())
    }

    fn write_footer(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

pub struct TableFormatter {
    writer: Box<dyn Write + Send>,
    wrote_header: bool,
}

impl TableFormatter {
    pub fn new(writer: Box<dyn Write + Send>) -> Self {
        Self {
            writer,
            wrote_header: false,
        }
    }
}

impl Formatter for TableFormatter {
    fn write_header(&mut self) -> io::Result<()> {
        writeln!(
            self.writer,
            "{:<30} {:>5} {:>8} {:>24} {:>24} {:>20} {:>30}",
            "HOST", "PORT", "DAYS", "NOT_BEFORE", "NOT_AFTER", "SUBJECT_CN", "ISSUER"
        )?;
        self.wrote_header = true;
        Ok(())
    }

    fn write_one(&mut self, record: &HostRecord) -> io::Result<()> {
        if !self.wrote_header {
            self.write_header()?;
        }
        if let Some(err) = &record.error {
            writeln!(
                self.writer,
                "{:<30} {:>5} {:>8} {:>24} {:>24} {:>20} {:>30}",
                record.host,
                record.port,
                "ERR",
                "-",
                "-",
                "-",
                err
            )?;
            return Ok(());
        }
        writeln!(
            self.writer,
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

    fn write_footer(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

pub struct TextFormatter {
    writer: Box<dyn Write + Send>,
}

impl TextFormatter {
    pub fn new(writer: Box<dyn Write + Send>) -> Self {
        Self { writer }
    }
}

impl Formatter for TextFormatter {
    fn write_header(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn write_one(&mut self, record: &HostRecord) -> io::Result<()> {
        if let Some(err) = &record.error {
            writeln!(
                self.writer,
                "{}:{} ERROR: {}",
                record.host, record.port, err
            )?;
            return Ok(());
        }
        writeln!(
            self.writer,
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

    fn write_footer(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}
