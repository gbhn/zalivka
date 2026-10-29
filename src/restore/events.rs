//! Restored progress, checkpoint diagnostics and optional transcript recording.
use crate::{
    logging::{Level, Record},
    wire,
};
use anyhow::{Context, Result};
use plist::Value;
use std::{collections::BTreeMap, io::Write};

pub(super) fn log_progress(
    message: &Value,
    mut output: impl FnMut(Record),
) -> Result<crate::progress::Event> {
    let operation = wire::get(message, &["Operation"])
        .and_then(wire::number)
        .context("invalid ProgressMsg.Operation")?;
    let value = wire::get(message, &["Progress"])?;
    let progress = value.as_signed_integer().with_context(|| {
        format!("invalid ProgressMsg.Progress: expected signed plist integer, got {value:?}")
    })?;
    output(Record::new(
        Level::Debug,
        "restored:op",
        if progress == -1 {
            format!("Operation {operation}: no percentage")
        } else if progress < 0 {
            format!("Operation {operation}: percentage unavailable ({progress})")
        } else {
            format!("Operation {operation}: {progress}%")
        },
    ));
    Ok(crate::progress::Event::OperationProgress {
        operation,
        progress,
    })
}

/// These optional weights are progress hints, not a condition for restoring.
pub(super) fn operation_weights(message: &Value) -> Option<crate::progress::Event> {
    let weights =
        wire::dictionary(wire::get(message, &["OperationWeights", "operation_weights"]).ok()?)
            .ok()?;
    let ids =
        wire::dictionary(wire::get(message, &["OperationWeights", "operation_ids"]).ok()?).ok()?;
    let mut operations = BTreeMap::new();
    for (key, value) in weights {
        let operation = wire::number(ids.get(key)?).ok()?;
        let weight = wire::number(value).ok()?;
        if operations.insert(operation, weight).is_some() {
            return None;
        }
    }
    operations
        .values()
        .any(|weight| *weight > 0)
        .then_some(())?;
    let mut progresses = BTreeMap::new();
    if let Some(values) =
        wire::optional(message, &["OperationWeights", "operation_progresses"]).ok()?
    {
        for (key, value) in wire::dictionary(values).ok()? {
            let operation = wire::number(ids.get(key)?).ok()?;
            let weight = operations.get(&operation)?;
            // Apple's PRProgressDecodeWeights stores completed weight units.
            // Values above the operation's weight are capped by its decoder.
            let completed = wire::number(value).ok()?.min(*weight);
            if progresses.insert(operation, completed).is_some() {
                return None;
            }
        }
    }
    Some(crate::progress::Event::OperationWeights {
        weights: operations.into_iter().collect(),
        progresses: progresses.into_iter().collect(),
    })
}

pub(super) fn log_checkpoint(
    message: &Value,
    mut output: impl FnMut(Record),
) -> Result<(crate::progress::Event, bool)> {
    let id = wire::number(wire::get(message, &["CHECKPOINT_ID"])?)?;
    let name = wire::string(message, &["CHECKPOINT_NAME"]).unwrap_or("unknown");
    let result = wire::get(message, &["CHECKPOINT_RESULT"])?
        .as_signed_integer()
        .context("invalid checkpoint result")?;
    let complete = wire::optional_boolean(message, &["CHECKPOINT_COMPLETE"])?.unwrap_or(false);
    let phase = if complete { "completed" } else { "started" };
    // Checkpoints describe individual steps; only StatusMsg decides the final result.
    output(Record::new(
        if result == 0 {
            Level::Debug
        } else {
            Level::Warning
        },
        "restored:cp",
        format!("{name}: {phase}; id=0x{id:x}, result={result}"),
    ));
    let error = wire::string(message, &["CHECKPOINT_ERROR"]).ok();
    for (text, level) in [
        (
            wire::string(message, &["CHECKPOINT_WARNING"]).ok(),
            Level::Warning,
        ),
        (error, Level::Error),
    ] {
        if let Some(text) = text {
            output(Record::new(
                level,
                "restored:cp",
                format!("{name} (0x{id:x}): {text}"),
            ));
        }
    }
    if !complete {
        output(Record::new(
            Level::Info,
            "restore",
            format!("Mac stage: {}", name.replace('_', " ")),
        ));
    }
    let provisioning_failed = complete
        && matches!(name, "create_production_ucrt" | "create_production_dcrt")
        && (result != 0 || error.is_some_and(|error| !error.trim().is_empty()));
    Ok((
        crate::progress::Event::Checkpoint {
            name: name.into(),
            complete,
        },
        provisioning_failed,
    ))
}

/// Once firmware is running, a diagnostic write must not interrupt the device
/// protocol. A partial JSON line also makes the transcript unsafe to append to.
pub(super) fn record_message(log: &mut Option<impl Write>, message: &Value) -> Option<Record> {
    let output = log.as_mut()?;
    let result = (|| -> Result<()> {
        serde_json::to_writer(&mut *output, message)?;
        output.write_all(b"\n")?;
        output.flush()?;
        Ok(())
    })();
    let error = result.err()?;
    *log = None;
    Some(Record::new(
        Level::Warning,
        "transcript",
        format!(
            "JSONL journal incomplete: {error:#}. Further recording disabled; restore continues."
        ),
    ))
}
