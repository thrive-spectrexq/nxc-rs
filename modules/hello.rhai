// Sample nxc-rs script module
fn run(session, opts) {
    let target = session.get("target");
    let protocol = session.get("protocol");
    
    return "Hello from Rhai! Targeting " + target + " via " + protocol;
}
