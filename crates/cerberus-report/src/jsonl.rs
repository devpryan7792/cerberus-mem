//! JSON-Lines streaming emitter.

use crate::models::ForensicFinding;
use std::io::Write;

/// Errors produced while emitting JSON-Lines.
#[derive(Debug, thiserror::Error)]
pub enum JsonlError {
    /// Serialization failed.
    #[error("failed to serialize finding: {0}")]
    Serialize(#[from] serde_json::Error),
    /// Writing or flushing failed.
    #[error("failed to write finding: {0}")]
    Io(#[from] std::io::Error),
}

/// Streaming emitter that writes one JSON object per line.
pub struct JsonlEmitter<W: Write> {
    writer: W,
}

impl<W: Write> JsonlEmitter<W> {
    /// Create an emitter around `writer`.
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    /// Serialize and emit one finding followed by a newline.
    pub fn emit(&mut self, finding: &ForensicFinding) -> Result<(), JsonlError> {
        serde_json::to_writer(&mut self.writer, finding)?;
        self.writer.write_all(b"\n")?;
        Ok(())
    }

    /// Emit several findings in order.
    pub fn emit_all(&mut self, findings: &[ForensicFinding]) -> Result<(), JsonlError> {
        for finding in findings {
            self.emit(finding)?;
        }
        Ok(())
    }

    /// Flush the underlying writer.
    pub fn flush(&mut self) -> Result<(), JsonlError> {
        self.writer.flush()?;
        Ok(())
    }

    /// Consume the emitter and return the inner writer.
    pub fn into_inner(self) -> W {
        self.writer
    }
}
