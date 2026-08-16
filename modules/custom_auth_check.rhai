// custom_auth_check.rhai — Sample Rhai module for credential auditing and options parsing
fn run(session, opts) {
    let target = session.get("target");
    let protocol = session.get("protocol");

    let custom_tag = if opts.contains_key("TAG") {
        opts.get("TAG")
    } else {
        "AUDIT"
    };

    return `[${custom_tag}] Verified active ${protocol} session against ${target}`;
}
