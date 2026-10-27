//! IKEv2 registry values (RFC 7296 §3 and the IANA "IKEv2 Parameters").

pub mod exchange {
    pub const IKE_SA_INIT: u8 = 34;
    pub const IKE_AUTH: u8 = 35;
    pub const CREATE_CHILD_SA: u8 = 36;
    pub const INFORMATIONAL: u8 = 37;
}

pub mod flags {
    pub const INITIATOR: u8 = 0x08;
    pub const RESPONSE: u8 = 0x20;
}

pub mod payload {
    pub const NONE: u8 = 0;
    pub const SA: u8 = 33;
    pub const KE: u8 = 34;
    pub const IDI: u8 = 35;
    pub const IDR: u8 = 36;
    pub const CERT: u8 = 37;
    pub const CERTREQ: u8 = 38;
    pub const AUTH: u8 = 39;
    pub const NONCE: u8 = 40;
    pub const NOTIFY: u8 = 41;
    pub const DELETE: u8 = 42;
    pub const TSI: u8 = 44;
    pub const TSR: u8 = 45;
    pub const SK: u8 = 46;
    pub const CP: u8 = 47;
    pub const EAP: u8 = 48;
}

pub mod protocol {
    pub const IKE: u8 = 1;
    pub const ESP: u8 = 3;
}

pub mod transform {
    pub const ENCR: u8 = 1;
    pub const PRF: u8 = 2;
    pub const INTEG: u8 = 3;
    pub const DH: u8 = 4;
    pub const ESN: u8 = 5;
    /// Attribute type "Key Length" (TV format).
    pub const ATTR_KEY_LENGTH: u16 = 14;
}

pub mod notify {
    pub const UNSUPPORTED_CRITICAL_PAYLOAD: u16 = 1;
    pub const INVALID_IKE_SPI: u16 = 4;
    pub const INVALID_MAJOR_VERSION: u16 = 5;
    pub const INVALID_SYNTAX: u16 = 7;
    pub const INVALID_MESSAGE_ID: u16 = 9;
    pub const INVALID_SPI: u16 = 11;
    pub const NO_PROPOSAL_CHOSEN: u16 = 14;
    pub const INVALID_KE_PAYLOAD: u16 = 17;
    pub const AUTHENTICATION_FAILED: u16 = 24;
    pub const SINGLE_PAIR_REQUIRED: u16 = 34;
    pub const NO_ADDITIONAL_SAS: u16 = 35;
    pub const INTERNAL_ADDRESS_FAILURE: u16 = 36;
    pub const FAILED_CP_REQUIRED: u16 = 37;
    pub const TS_UNACCEPTABLE: u16 = 38;
    pub const TEMPORARY_FAILURE: u16 = 43;
    pub const CHILD_SA_NOT_FOUND: u16 = 44;
    /// First status (non-error) type.
    pub const FIRST_STATUS: u16 = 16384;
    pub const INITIAL_CONTACT: u16 = 16384;
    pub const NAT_DETECTION_SOURCE_IP: u16 = 16388;
    pub const NAT_DETECTION_DESTINATION_IP: u16 = 16389;
    pub const COOKIE: u16 = 16390;
    pub const REKEY_SA: u16 = 16393;
    /// RFC 7427.
    pub const SIGNATURE_HASH_ALGORITHMS: u16 = 16431;

    /// Human-readable name and hint for error notifications.
    pub fn describe(kind: u16) -> String {
        let (name, hint) = match kind {
            UNSUPPORTED_CRITICAL_PAYLOAD => ("UNSUPPORTED_CRITICAL_PAYLOAD", ""),
            INVALID_IKE_SPI => ("INVALID_IKE_SPI", ""),
            INVALID_MAJOR_VERSION => ("INVALID_MAJOR_VERSION", " (the gateway phase1 may be IKEv1)"),
            INVALID_SYNTAX => ("INVALID_SYNTAX", ""),
            INVALID_MESSAGE_ID => ("INVALID_MESSAGE_ID", ""),
            INVALID_SPI => ("INVALID_SPI", ""),
            NO_PROPOSAL_CHOSEN => {
                ("NO_PROPOSAL_CHOSEN", " (align the profile's ike/esp proposals with the gateway phase1/phase2)")
            }
            INVALID_KE_PAYLOAD => ("INVALID_KE_PAYLOAD", ""),
            AUTHENTICATION_FAILED => (
                "AUTHENTICATION_FAILED",
                " (check the pre-shared key, local_id/peer ID, EAP credentials or client certificate)",
            ),
            SINGLE_PAIR_REQUIRED => ("SINGLE_PAIR_REQUIRED", ""),
            NO_ADDITIONAL_SAS => ("NO_ADDITIONAL_SAS", ""),
            INTERNAL_ADDRESS_FAILURE => ("INTERNAL_ADDRESS_FAILURE", " (address pool exhausted?)"),
            FAILED_CP_REQUIRED => ("FAILED_CP_REQUIRED", ""),
            TS_UNACCEPTABLE => ("TS_UNACCEPTABLE", " (check the phase2 selectors)"),
            TEMPORARY_FAILURE => ("TEMPORARY_FAILURE", ""),
            CHILD_SA_NOT_FOUND => ("CHILD_SA_NOT_FOUND", ""),
            _ => return format!("error notification {kind}"),
        };
        format!("{name}{hint}")
    }
}

pub mod id_type {
    pub const IPV4_ADDR: u8 = 1;
    pub const FQDN: u8 = 2;
    pub const RFC822_ADDR: u8 = 3;
    pub const DER_ASN1_DN: u8 = 9;
    pub const KEY_ID: u8 = 11;
}

pub mod auth_method {
    pub const RSA_SIGNATURE: u8 = 1;
    pub const SHARED_KEY_MIC: u8 = 2;
    /// RFC 4754.
    pub const ECDSA_SHA256_P256: u8 = 9;
    pub const ECDSA_SHA384_P384: u8 = 10;
    pub const ECDSA_SHA512_P521: u8 = 11;
    /// RFC 7427.
    pub const DIGITAL_SIGNATURE: u8 = 14;
}

pub mod cfg {
    pub const REQUEST: u8 = 1;
    #[cfg(test)]
    pub const REPLY: u8 = 2;
    pub const INTERNAL_IP4_ADDRESS: u16 = 1;
    pub const INTERNAL_IP4_DNS: u16 = 3;
    pub const INTERNAL_IP4_SUBNET: u16 = 13;
    /// RFC 8598.
    pub const INTERNAL_DNS_DOMAIN: u16 = 25;
}

pub mod ts_type {
    pub const IPV4_ADDR_RANGE: u8 = 7;
}
