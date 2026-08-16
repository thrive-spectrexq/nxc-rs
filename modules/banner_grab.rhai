// banner_grab.rhai — Sample Rhai module for banner and target info inspection
fn run(session, opts) {
    let target = session.get("target");
    let protocol = session.get("protocol");
    let is_admin = session.get("is_admin");

    let status = if is_admin {
        "[Pwn3d!] Administrator access verified"
    } else {
        "[+] Standard user access verified"
    };

    return `[${protocol}] Target: ${target} -> ${status}`;
}
