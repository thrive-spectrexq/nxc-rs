# Kubernetes Protocol

NetExec-RS v0.4.0 introduces the `kube` protocol testing capabilities for probing highly-exposed or misconfigured Kubernetes clusters.

## Execution Basics

Kubernetes API servers typical run on port `6443` or `8443` over TLS.

```bash
# General anonymous port check
nxc kube 10.10.0.0/16 
```

To execute authenticated operations, supply a harvested Service Account Token instead of a password.

```bash
# Pass the token for targeted execution
nxc kube 10.10.10.20 -u <service_account> -p "eyJhbGci..."
```

## Modules

### 1. Anonymous Access Check
Checks if the Kubelet or apiserver allows unauthenticated access (often returns the raw Swagger/OpenAPI definition).
```bash
nxc kube <target> -M check_anon
```

### 2. Namespace Enumeration
Dumps all active namespaces mapped in the cluster.
```bash
nxc kube <target> -M enum_namespaces
```

### 3. Dump Secrets & Pods
Leverages a discovered JWT token to dump cluster infrastructure secrets.
```bash
nxc kube <target> -u system:serviceaccount:default -p <Token> -M dump_secrets
```

> [!WARNING]
> Testing Kubernetes APIs is often loud and generates heavily serialized audit logs within the master plane. Use `kube` enumeration surgically.
