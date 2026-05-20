#![allow(clippy::unwrap_used)]

use nxc_db::{backend::*, HostInfo, Credential, AuthResultEntry, NxcDb};
use tempfile::tempdir;

async fn setup_db() -> (Box<dyn DatabaseBackend>, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("nxc_test.db");
    (Box::new(NxcDb::new(&db_path, "default").unwrap()), dir)
}

#[tokio::test]
async fn test_upsert_and_list_hosts() {
    let (db, _dir) = setup_db().await;
    let host = HostInfo {
        id: None,
        workspace: "default".to_string(),
        ip: "10.0.0.1".to_string(),
        hostname: Some("DC01".to_string()),
        domain: Some("CORP".to_string()),
        os: Some("Windows Server 2022".to_string()),
        os_version: None,
        smb_signing: Some(true),
        signing_required: Some(true),
        is_dc: true,
        first_seen: 100,
        last_seen: 100,
    };

    let id = db.upsert_host(&host).await.unwrap();
    assert!(id > 0);

    let hosts = db.list_hosts("default").await.unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].ip, "10.0.0.1");
}

#[tokio::test]
async fn test_credentials_crud() {
    let (db, _dir) = setup_db().await;
    let host = HostInfo {
        id: None,
        workspace: "default".to_string(),
        ip: "10.0.0.2".to_string(),
        hostname: None,
        domain: None,
        os: None,
        os_version: None,
        smb_signing: None,
        signing_required: None,
        is_dc: false,
        first_seen: 0,
        last_seen: 0,
    };
    let host_id = db.upsert_host(&host).await.unwrap();

    let cred = Credential {
        id: None,
        workspace: "default".to_string(),
        domain: Some("CORP".to_string()),
        username: "admin".to_string(),
        password: Some("Pass123!".to_string()),
        nt_hash: None,
        lm_hash: None,
        aes_128: None,
        aes_256: None,
        source: Some("memory".to_string()),
        host_id: Some(host_id),
        created_at: 0,
    };

    let cred_id = db.add_credential(&cred).await.unwrap();
    assert!(cred_id > 0);

    let creds = db.search_credentials("default", None, None, false).await.unwrap();
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].username, "admin");

    db.delete_credential(cred_id).await.unwrap();
    let creds_after = db.search_credentials("default", None, None, false).await.unwrap();
    assert_eq!(creds_after.len(), 0);
}

#[tokio::test]
async fn test_auth_results() {
    let (db, _dir) = setup_db().await;
    let host_id = db.upsert_host(&HostInfo {
        id: None,
        workspace: "default".to_string(),
        ip: "10.0.0.3".to_string(),
        hostname: None,
        domain: None,
        os: None,
        os_version: None,
        smb_signing: None,
        signing_required: None,
        is_dc: false,
        first_seen: 0,
        last_seen: 0,
    }).await.unwrap();

    let res = AuthResultEntry {
        id: None,
        host_id,
        credential_id: None,
        protocol: "smb".to_string(),
        status: "success".to_string(),
        admin: true,
        attempted_at: 1000,
    };

    let res_id = db.add_auth_result(&res).await.unwrap();
    assert!(res_id > 0);

    let stats = db.get_stats("default").await.unwrap();
    assert_eq!(stats.admin_accesses, 1);
}

#[tokio::test]
async fn test_vulnerabilities_and_attack_chains() {
    let (db, _dir) = setup_db().await;
    let host_id = db.upsert_host(&HostInfo {
        id: None,
        workspace: "default".to_string(),
        ip: "10.0.0.4".to_string(),
        hostname: None,
        domain: None,
        os: None,
        os_version: None,
        smb_signing: None,
        signing_required: None,
        is_dc: false,
        first_seen: 0,
        last_seen: 0,
    }).await.unwrap();

    let vuln = Vulnerability {
        id: None,
        host_id,
        cve_id: Some("CVE-2020-1472".to_string()),
        title: "Zerologon".to_string(),
        severity: "critical".to_string(),
        description: Some("Netlogon privilege escalation".to_string()),
        evidence: None,
        module_name: Some("zerologon".to_string()),
        detected_at: 12345,
    };

    let vuln_id = db.add_vulnerability(&vuln).await.unwrap();
    assert!(vuln_id > 0);

    let chain = AttackChain {
        id: None,
        workspace: "default".to_string(),
        name: "Zerologon to DA".to_string(),
        description: Some("Reset machine account password and DCSync".to_string()),
        steps: "[{\"step\": 1, \"action\": \"zerologon\"}]".to_string(),
        risk_score: Some(9.8),
        created_at: 12345,
    };

    let chain_id = db.add_attack_chain(&chain).await.unwrap();
    assert!(chain_id > 0);
}

#[tokio::test]
async fn test_operations_log() {
    let (db, _dir) = setup_db().await;
    let log = OperationsLog {
        id: None,
        workspace: "default".to_string(),
        operation: "scan".to_string(),
        target: Some("10.0.0.0/24".to_string()),
        module: None,
        status: "completed".to_string(),
        details: Some("Found 10 hosts".to_string()),
        started_at: 100,
        completed_at: Some(200),
    };

    let log_id = db.log_operation(&log).await.unwrap();
    assert!(log_id > 0);
}
