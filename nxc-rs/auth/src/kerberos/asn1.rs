use rasn::prelude::*;

pub type KerberosFlags = BitString;
pub type Microseconds = i32;
pub type Int32 = i32;
pub type UInt32 = u32;
pub type KerberosTime = GeneralizedTime;

/// Kerberos uses GeneralString for realm/principal names, but in practice
/// these are always ASCII. This helper creates a GeneralString from a Rust &str.
pub fn krb_string(s: &str) -> GeneralString {
    GeneralString::try_from(s).unwrap_or_else(|_| GeneralString::try_from("").unwrap_or_else(|_| panic!("Failed to create empty GeneralString")))
}

#[derive(AsnType, Encode, Decode, Debug, Clone)]
#[rasn(delegate)]
pub struct Realm(pub GeneralString);

impl Realm {
    pub fn new(s: &str) -> Self {
        Self(krb_string(s))
    }
}

#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct PrincipalName {
    #[rasn(tag(context, 0))]
    pub name_type: Int32,
    #[rasn(tag(context, 1))]
    pub name_string: SequenceOf<GeneralString>,
}

impl PrincipalName {
    pub fn new(name_type: Int32, names: &[&str]) -> Self {
        Self { name_type, name_string: names.iter().map(|s| krb_string(s)).collect() }
    }
}

#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct Ticket {
    #[rasn(tag(context, 0))]
    pub tkt_vno: Int32,
    #[rasn(tag(context, 1))]
    pub realm: Realm,
    #[rasn(tag(context, 2))]
    pub sname: PrincipalName,
    #[rasn(tag(context, 3))]
    pub enc_part: EncryptedData,
}

#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct EncryptedData {
    #[rasn(tag(context, 0))]
    pub etype: Int32,
    #[rasn(tag(context, 1))]
    pub kvno: Option<UInt32>,
    #[rasn(tag(context, 2))]
    pub cipher: OctetString,
}

#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct PaData {
    #[rasn(tag(context, 1))]
    pub padata_type: Int32,
    #[rasn(tag(context, 2))]
    pub padata_value: OctetString,
}

#[derive(AsnType, Encode, Decode, Debug, Clone)]
#[rasn(tag(application, 10))]
pub struct AsReq(pub KdcReq);

#[derive(AsnType, Encode, Decode, Debug, Clone)]
#[rasn(tag(application, 12))]
pub struct TgsReq(pub KdcReq);

#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct KdcReq {
    #[rasn(tag(context, 1))]
    pub pvno: Int32,
    #[rasn(tag(context, 2))]
    pub msg_type: Int32,
    #[rasn(tag(context, 3))]
    pub padata: Option<SequenceOf<PaData>>,
    #[rasn(tag(context, 4))]
    pub req_body: KdcReqBody,
}

#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct KdcReqBody {
    #[rasn(tag(context, 0))]
    pub kdc_options: KerberosFlags,
    #[rasn(tag(context, 1))]
    pub cname: Option<PrincipalName>,
    #[rasn(tag(context, 2))]
    pub realm: Realm,
    #[rasn(tag(context, 3))]
    pub sname: Option<PrincipalName>,
    #[rasn(tag(context, 4))]
    pub from: Option<KerberosTime>,
    #[rasn(tag(context, 5))]
    pub till: KerberosTime,
    #[rasn(tag(context, 6))]
    pub rtime: Option<KerberosTime>,
    #[rasn(tag(context, 7))]
    pub nonce: UInt32,
    #[rasn(tag(context, 8))]
    pub etype: SequenceOf<Int32>,
    #[rasn(tag(context, 9))]
    pub addresses: Option<SequenceOf<HostAddress>>,
    #[rasn(tag(context, 10))]
    pub enc_authorization_data: Option<EncryptedData>,
    #[rasn(tag(context, 11))]
    pub additional_tickets: Option<SequenceOf<Ticket>>,
}

#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct HostAddress {
    #[rasn(tag(context, 0))]
    pub addr_type: Int32,
    #[rasn(tag(context, 1))]
    pub address: OctetString,
}

#[derive(AsnType, Encode, Decode, Debug, Clone)]
#[rasn(tag(application, 11))]
pub struct AsRep(pub KdcRep);

#[derive(AsnType, Encode, Decode, Debug, Clone)]
#[rasn(tag(application, 13))]
pub struct TgsRep(pub KdcRep);

#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct KdcRep {
    #[rasn(tag(context, 0))]
    pub pvno: Int32,
    #[rasn(tag(context, 1))]
    pub msg_type: Int32,
    #[rasn(tag(context, 2))]
    pub padata: Option<SequenceOf<PaData>>,
    #[rasn(tag(context, 3))]
    pub crealm: Realm,
    #[rasn(tag(context, 4))]
    pub cname: PrincipalName,
    #[rasn(tag(context, 5))]
    pub ticket: Ticket,
    #[rasn(tag(context, 6))]
    pub enc_part: EncryptedData,
}

#[derive(AsnType, Encode, Decode, Debug, Clone)]
#[rasn(tag(application, 14))]
pub struct ApReq {
    #[rasn(tag(context, 0))]
    pub pvno: Int32,
    #[rasn(tag(context, 1))]
    pub msg_type: Int32,
    #[rasn(tag(context, 2))]
    pub ap_options: KerberosFlags,
    #[rasn(tag(context, 3))]
    pub ticket: Ticket,
    #[rasn(tag(context, 4))]
    pub authenticator: EncryptedData,
}

#[derive(AsnType, Encode, Decode, Debug, Clone)]
#[rasn(tag(application, 2))]
pub struct Authenticator {
    #[rasn(tag(context, 0))]
    pub authenticator_vno: Int32,
    #[rasn(tag(context, 1))]
    pub crealm: Realm,
    #[rasn(tag(context, 2))]
    pub cname: PrincipalName,
    #[rasn(tag(context, 3))]
    pub cksum: Option<Checksum>,
    #[rasn(tag(context, 4))]
    pub cusec: Microseconds,
    #[rasn(tag(context, 5))]
    pub ctime: KerberosTime,
    #[rasn(tag(context, 6))]
    pub subkey: Option<EncryptionKey>,
    #[rasn(tag(context, 7))]
    pub seq_number: Option<UInt32>,
    #[rasn(tag(context, 8))]
    pub authorization_data: Option<AuthorizationData>,
}

#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct EncryptionKey {
    #[rasn(tag(context, 0))]
    pub keytype: Int32,
    #[rasn(tag(context, 1))]
    pub keyvalue: OctetString,
}

#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct Checksum {
    #[rasn(tag(context, 0))]
    pub cksumtype: Int32,
    #[rasn(tag(context, 1))]
    pub checksum: OctetString,
}

#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct AuthorizationDataElement {
    #[rasn(tag(context, 0))]
    pub ad_type: Int32,
    #[rasn(tag(context, 1))]
    pub ad_data: OctetString,
}

pub type AuthorizationData = SequenceOf<AuthorizationDataElement>;

#[derive(AsnType, Encode, Decode, Debug, Clone)]
#[rasn(tag(application, 25))]
pub struct EncAsRepPart(pub EncKdcRepPart);

#[derive(AsnType, Encode, Decode, Debug, Clone)]
#[rasn(tag(application, 26))]
pub struct EncTgsRepPart(pub EncKdcRepPart);

#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct EncKdcRepPart {
    #[rasn(tag(context, 0))]
    pub key: EncryptionKey,
    #[rasn(tag(context, 1))]
    pub last_req: LastReq,
    #[rasn(tag(context, 2))]
    pub nonce: UInt32,
    #[rasn(tag(context, 3))]
    pub key_expiration: Option<KerberosTime>,
    #[rasn(tag(context, 4))]
    pub flags: KerberosFlags,
    #[rasn(tag(context, 5))]
    pub authtime: KerberosTime,
    #[rasn(tag(context, 6))]
    pub starttime: Option<KerberosTime>,
    #[rasn(tag(context, 7))]
    pub endtime: KerberosTime,
    #[rasn(tag(context, 8))]
    pub renew_till: Option<KerberosTime>,
    #[rasn(tag(context, 9))]
    pub srealm: Realm,
    #[rasn(tag(context, 10))]
    pub sname: PrincipalName,
    #[rasn(tag(context, 11))]
    pub caddr: Option<SequenceOf<HostAddress>>,
}

pub type LastReq = SequenceOf<LastReqElement>;

#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct LastReqElement {
    #[rasn(tag(context, 0))]
    pub lr_type: Int32,
    #[rasn(tag(context, 1))]
    pub lr_value: KerberosTime,
}
