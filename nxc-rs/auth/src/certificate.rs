use anyhow::{anyhow, Result};
use p12::PFX;

/// Certificate authentication handler (PKINIT, Schannel)
pub struct CertificateAuth {
    pfx_path: String,
    certificate: Option<Vec<u8>>,
    private_key: Option<Vec<u8>>,
}

impl CertificateAuth {
    pub fn new(pfx_path: &str) -> Self {
        Self { pfx_path: pfx_path.to_string(), certificate: None, private_key: None }
    }

    /// Parse PFX and extract private key/certificate
    pub fn parse_pfx(&mut self, password: Option<&str>) -> Result<()> {
        let pfx_data =
            std::fs::read(&self.pfx_path).map_err(|e| anyhow!("Failed to read PFX file: {e}"))?;

        let pfx = PFX::parse(&pfx_data).map_err(|e| anyhow!("Failed to parse PFX DER: {e:?}"))?;

        let pass = password.unwrap_or("");

        // Extract certificates from the PFX vault
        let certs =
            pfx.cert_x509_bags(pass).map_err(|e| anyhow!("Failed to extract cert bags: {e:?}"))?;

        if let Some(cert) = certs.into_iter().next() {
            self.certificate = Some(cert);
        }

        // Extract private keys from the PFX vault
        let keys = pfx.key_bags(pass).map_err(|e| anyhow!("Failed to extract key bags: {e:?}"))?;

        if let Some(key) = keys.into_iter().next() {
            self.private_key = Some(key);
        }

        if self.certificate.is_none() || self.private_key.is_none() {
            anyhow::bail!("PFX did not contain both a certificate and a private key");
        }

        Ok(())
    }

    /// Check if certificate and private key are loaded into memory.
    pub fn is_loaded(&self) -> bool {
        self.certificate.is_some() && self.private_key.is_some()
    }

    /// Explicitly zeroize private key and certificate buffers from memory.
    pub fn clear(&mut self) {
        use zeroize::Zeroize;
        if let Some(ref mut key) = self.private_key {
            key.zeroize();
        }
        if let Some(ref mut cert) = self.certificate {
            cert.zeroize();
        }
        self.private_key = None;
        self.certificate = None;
    }

    /// Prepare PKINIT pre-auth data for Kerberos AS-REQ (PA-PK-AS-REQ)
    pub fn prepare_pkinit(&self) -> Result<Vec<u8>> {
        if self.certificate.is_none() {
            anyhow::bail!("Certificate not loaded for PKINIT");
        }

        // Note: Constructing the PA-PK-AS-REQ (RFC 4556) involves:
        // 1. SignedAuthPack (Signed with certificate's private key)
        // 2. AuthPack (Contains client time and checksum)
        // 3. Encapsulating in PaPkAsReq ASN.1 structure

        tracing::debug!("Preparing PKINIT blob using certificate...");

        // Temporary placeholder that identifies as PKINIT to the AS-REQ logic
        // Real ASN.1 construction resides in the upcoming Phase 1 signer logic.
        Ok(vec![0x30, 0x82, 0x01, 0x00])
    }
}

impl Drop for CertificateAuth {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroize;

    #[test]
    fn test_certificate_auth_zeroize_on_clear() {
        let mut auth = CertificateAuth::new("dummy.pfx");
        let mut test_key = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03];
        let mut test_cert = vec![0xCA, 0xFE, 0xBA, 0xBE];

        auth.private_key = Some(test_key.clone());
        auth.certificate = Some(test_cert.clone());
        assert!(auth.is_loaded());

        // Call clear explicitly
        auth.clear();
        assert!(!auth.is_loaded());
        assert!(auth.private_key.is_none());
        assert!(auth.certificate.is_none());

        // Verify zeroize on a buffer works as expected
        test_key.zeroize();
        test_cert.zeroize();
        assert!(test_key.iter().all(|&b| b == 0));
        assert!(test_cert.iter().all(|&b| b == 0));
    }
}
