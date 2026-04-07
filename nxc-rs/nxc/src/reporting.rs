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
    
    // Write header
    writer.write_record(&[
        "target", "protocol", "username", "success", "admin", "message", "duration_ms", "module_data"
    ])?;

    for res in results {
        let module_data_json = serde_json::to_string(&res.module_data).unwrap_or_else(|_| "{}".to_string());
        writer.write_record(&[
            &res.target,
            &res.protocol,
            &res.username,
            &res.success.to_string(),
            &res.admin.to_string(),
            &res.message,
            &res.duration_ms.to_string(),
            &module_data_json,
        ])?;
    }
    writer.flush()?;
    Ok(())
}
