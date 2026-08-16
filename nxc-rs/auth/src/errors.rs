use thiserror::Error;

/// Core error hierarchy for `nxc-auth`.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("NTLM authentication error: {0}")]
    Ntlm(#[from] NtlmError),

    #[error("Kerberos authentication error: {0}")]
    Kerberos(#[from] KerberosError),

    #[error("Certificate authentication error: {0}")]
    Certificate(#[from] CertificateError),

    #[error("Registry secrets extraction error: {0}")]
    Registry(#[from] RegistryError),

    #[error("Unsupported authentication method: {0}")]
    UnsupportedAuthMethod(String),

    #[error("Missing credential: {0}")]
    MissingCredential(String),

    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),
}

#[derive(Debug, Error)]
pub enum NtlmError {
    #[error("Invalid NTLM message length: expected at least {expected}, got {actual}")]
    InvalidMessageLength { expected: usize, actual: usize },

    #[error("Invalid NTLM signature / magic bytes")]
    InvalidSignature,

    #[error("Invalid NTLM message type: {0}")]
    InvalidMessageType(u32),

    #[error("NTLM TargetInfo parsing failed: {0}")]
    TargetInfoParseError(String),

    #[error("NTLM challenge response computation failed: {0}")]
    ComputationFailed(String),
}

#[derive(Debug, Error)]
pub enum KerberosError {
    #[error("KDC connection failed to {0}: {1}")]
    KdcConnectionFailed(String, String),

    #[error("KDC returned Kerberos error code {code}: {message}")]
    KdcError { code: u32, message: String },

    #[error("Kerberos ASN.1 decoding error: {0}")]
    Asn1DecodeError(String),

    #[error("Kerberos ticket decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid or expired Kerberos ccache file: {0}")]
    CcacheError(String),
}

#[derive(Debug, Error)]
pub enum CertificateError {
    #[error("PKCS#12 archive parsing failed: {0}")]
    Pkcs12ParseError(String),

    #[error("X.509 certificate decoding failed: {0}")]
    X509DecodeError(String),

    #[error("Private key extraction failed: {0}")]
    KeyExtractionError(String),
}

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("Failed to parse registry hive: {0}")]
    HiveParseError(String),

    #[error("Bootkey / Syskey derivation failed: {0}")]
    SyskeyError(String),

    #[error("LSA secret decryption failed: {0}")]
    LsaSecretError(String),

    #[error("SAM hash decryption failed: {0}")]
    SamHashError(String),
}
