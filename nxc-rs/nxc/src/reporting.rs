use nxc_targets::ExecutionResult;
use serde::Serialize;
use std::fs::File;

use anyhow::Result;

#[derive(Serialize)]
pub struct Report {
    pub timestamp: String,
    pub protocol: String,
    pub results: Vec<ExecutionResult>,
}

pub fn export_json(path: &str, report: &Report) -> Result<()> {
    let file = File::create(path)?;
    serde_json::to_writer_pretty(file, report)?;
    Ok(())
}

pub fn export_csv(path: &str, results: &[ExecutionResult]) -> Result<()> {
    let file = File::create(path)?;
    let mut writer = csv::Writer::from_writer(file);
    
    // Write header manually if needed, or use serialize
    for res in results {
        writer.serialize(res)?;
    }
    writer.flush()?;
    Ok(())
}
