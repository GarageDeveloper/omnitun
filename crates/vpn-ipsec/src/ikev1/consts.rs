//! IKEv1 / ISAKMP registry values (RFC 2407, 2408, 2409, 3947, 3706,
//! draft-beaulieu-ike-xauth-02, draft-dukes-ike-mode-cfg-02, Cisco Unity).
//! Kept complete as a registry, hence unused values.
#![allow(dead_code)]

pub mod exchange {
    pub const IDENTITY_PROTECTION: u8 = 2;
    pub const AGGRESSIVE: u8 = 4;
    pub const INFORMATIONAL: u8 = 5;
    pub const TRANSACTION: u8 = 6;
    pub const QUICK: u8 = 32;
}

pub mod flags {
    pub const ENCRYPTION: u8 = 0x01;
}

pub mod payload {
    pub const NONE: u8 = 0;
    pub const SA: u8 = 1;
    pub const PROPOSAL: u8 = 2;
    pub const TRANSFORM: u8 = 3;
    pub const KE: u8 = 4;
    pub const ID: u8 = 5;
    pub const HASH: u8 = 8;
    pub const NONCE: u8 = 10;
    pub const NOTIFY: u8 = 11;
    pub const DELETE: u8 = 12;
    pub const VENDOR_ID: u8 = 13;
    pub const ATTRIBUTE: u8 = 14;
    /// RFC 3947.
    pub const NAT_D: u8 = 20;
    /// draft-ietf-ipsec-nat-t-ike-02/03.
    pub const NAT_D_DRAFT: u8 = 130;
    /// NAT original address (RFC 3947 and draft numbering).
    pub const NAT_OA: u8 = 21;
    pub const NAT_OA_DRAFT: u8 = 131;
}

pub const DOI_IPSEC: u32 = 1;
pub const SIT_IDENTITY_ONLY: u32 = 1;

pub mod protocol {
    pub const ISAKMP: u8 = 1;
    pub const ESP: u8 = 3;
}

/// Phase 1 (KEY_IKE transform) attributes, RFC 2409 Appendix A.
pub mod ike_attr {
    pub const ENCRYPTION: u16 = 1;
    pub const HASH: u16 = 2;
    pub const AUTH_METHOD: u16 = 3;
    pub const GROUP: u16 = 4;
    pub const LIFE_TYPE: u16 = 11;
    pub const LIFE_DURATION: u16 = 12;
    pub const KEY_LENGTH: u16 = 14;

    pub const ENCR_3DES_CBC: u64 = 5;
    pub const ENCR_AES_CBC: u64 = 7;
    pub const HASH_SHA1: u64 = 2;
    pub const HASH_SHA256: u64 = 4;
    pub const HASH_SHA384: u64 = 5;
    pub const HASH_SHA512: u64 = 6;
    pub const AUTH_PSK: u64 = 1;
    /// XAUTHInitPreShared (draft-beaulieu-ike-xauth-02 §8).
    pub const AUTH_XAUTH_INIT_PSK: u64 = 65001;
    pub const LIFE_SECONDS: u64 = 1;
    pub const TRANSFORM_KEY_IKE: u8 = 1;
}

/// Phase 2 (IPsec DOI) attributes, RFC 2407 §4.5.
pub mod esp_attr {
    pub const LIFE_TYPE: u16 = 1;
    pub const LIFE_DURATION: u16 = 2;
    pub const GROUP: u16 = 3;
    pub const ENCAPSULATION: u16 = 4;
    pub const AUTH_ALG: u16 = 5;
    pub const KEY_LENGTH: u16 = 6;

    pub const TRANSFORM_ESP_3DES: u8 = 3;
    pub const TRANSFORM_ESP_AES: u8 = 12;
    /// AES-GCM with a 16-byte ICV (RFC 4106 §8.1); no AUTH_ALG attribute.
    pub const TRANSFORM_ESP_AES_GCM_16: u8 = 20;
    pub const AUTH_HMAC_SHA1: u64 = 2;
    pub const AUTH_HMAC_SHA256: u64 = 5;
    pub const AUTH_HMAC_SHA384: u64 = 6;
    pub const AUTH_HMAC_SHA512: u64 = 7;
    pub const LIFE_SECONDS: u64 = 1;
    pub const LIFE_KILOBYTES: u64 = 2;
    /// UDP-Encapsulated-Tunnel, RFC 3947.
    pub const ENCAP_UDP_TUNNEL: u64 = 3;
    /// UDP-Encapsulated-Tunnel, NAT-T drafts.
    pub const ENCAP_UDP_TUNNEL_DRAFT: u64 = 61443;
    pub const ENCAP_UDP_TRANSPORT: u64 = 4;
    pub const ENCAP_UDP_TRANSPORT_DRAFT: u64 = 61444;
}

pub mod id_type {
    pub const IPV4_ADDR: u8 = 1;
    pub const FQDN: u8 = 2;
    pub const IPV4_ADDR_SUBNET: u8 = 4;
    pub const IPV4_ADDR_RANGE: u8 = 7;
}

pub mod notify {
    pub const INVALID_PAYLOAD_TYPE: u16 = 1;
    pub const DOI_NOT_SUPPORTED: u16 = 2;
    pub const INVALID_COOKIE: u16 = 4;
    pub const INVALID_EXCHANGE_TYPE: u16 = 7;
    pub const INVALID_FLAGS: u16 = 8;
    pub const INVALID_MESSAGE_ID: u16 = 9;
    pub const INVALID_SPI: u16 = 11;
    pub const ATTRIBUTES_NOT_SUPPORTED: u16 = 13;
    pub const NO_PROPOSAL_CHOSEN: u16 = 14;
    pub const PAYLOAD_MALFORMED: u16 = 16;
    pub const INVALID_KEY_INFORMATION: u16 = 17;
    pub const INVALID_ID_INFORMATION: u16 = 18;
    pub const INVALID_HASH_INFORMATION: u16 = 23;
    pub const AUTHENTICATION_FAILED: u16 = 24;
    /// Status notifications start here.
    pub const FIRST_STATUS: u16 = 16384;
    pub const RESPONDER_LIFETIME: u16 = 24576;
    pub const INITIAL_CONTACT: u16 = 24578;
    /// RFC 3706.
    pub const R_U_THERE: u16 = 36136;
    pub const R_U_THERE_ACK: u16 = 36137;

    pub fn describe(kind: u16) -> String {
        let (name, hint) = match kind {
            INVALID_PAYLOAD_TYPE => ("INVALID-PAYLOAD-TYPE", ""),
            DOI_NOT_SUPPORTED => ("DOI-NOT-SUPPORTED", ""),
            INVALID_COOKIE => ("INVALID-COOKIE", ""),
            INVALID_EXCHANGE_TYPE => {
                ("INVALID-EXCHANGE-TYPE", " (check the phase1 mode: main vs aggressive, and IKE version)")
            }
            INVALID_FLAGS => ("INVALID-FLAGS", ""),
            INVALID_MESSAGE_ID => ("INVALID-MESSAGE-ID", ""),
            INVALID_SPI => ("INVALID-SPI", ""),
            ATTRIBUTES_NOT_SUPPORTED => ("ATTRIBUTES-NOT-SUPPORTED", ""),
            NO_PROPOSAL_CHOSEN => (
                "NO-PROPOSAL-CHOSEN",
                " (align the profile's ike/esp proposals, DH/PFS groups and XAuth with the gateway)",
            ),
            PAYLOAD_MALFORMED => ("PAYLOAD-MALFORMED", ""),
            INVALID_KEY_INFORMATION => ("INVALID-KEY-INFORMATION", ""),
            INVALID_ID_INFORMATION => ("INVALID-ID-INFORMATION", " (check local_id / the gateway's peer ID)"),
            INVALID_HASH_INFORMATION => ("INVALID-HASH-INFORMATION", " (pre-shared key mismatch?)"),
            AUTHENTICATION_FAILED => ("AUTHENTICATION-FAILED", " (pre-shared key or identity rejected)"),
            _ => return format!("error notification {kind}"),
        };
        format!("{name}{hint}")
    }
}

/// Mode-Config / XAuth (attribute payload).
pub mod cfg {
    pub const REQUEST: u8 = 1;
    pub const REPLY: u8 = 2;
    pub const SET: u8 = 3;
    pub const ACK: u8 = 4;

    pub const INTERNAL_IP4_ADDRESS: u16 = 1;
    pub const INTERNAL_IP4_NETMASK: u16 = 2;
    pub const INTERNAL_IP4_DNS: u16 = 3;
    pub const INTERNAL_IP4_SUBNET: u16 = 13;

    pub const XAUTH_TYPE: u16 = 16520;
    pub const XAUTH_USER_NAME: u16 = 16521;
    pub const XAUTH_USER_PASSWORD: u16 = 16522;
    pub const XAUTH_PASSCODE: u16 = 16523;
    pub const XAUTH_MESSAGE: u16 = 16524;
    pub const XAUTH_CHALLENGE: u16 = 16525;
    pub const XAUTH_DOMAIN: u16 = 16526;
    pub const XAUTH_STATUS: u16 = 16527;
    pub const XAUTH_NEXT_PIN: u16 = 16528;
    pub const XAUTH_ANSWER: u16 = 16529;

    pub const UNITY_BANNER: u16 = 28672;
    pub const UNITY_DEF_DOMAIN: u16 = 28674;
    pub const UNITY_SPLITDNS_NAME: u16 = 28675;
    pub const UNITY_SPLIT_INCLUDE: u16 = 28676;
    pub const UNITY_LOCAL_LAN: u16 = 28678;

    /// Attributes whose value is a 16-bit basic (TV) value.
    pub fn is_basic(kind: u16) -> bool {
        matches!(kind, XAUTH_TYPE | XAUTH_STATUS)
    }
}

/// Vendor IDs we send and recognise.
pub mod vid {
    /// MD5("RFC 3947").
    pub const NAT_T_RFC3947: [u8; 16] = *b"\x4a\x13\x1c\x81\x07\x03\x58\x45\x5c\x57\x28\xf2\x0e\x95\x45\x2f";
    /// MD5("draft-ietf-ipsec-nat-t-ike-02\n").
    pub const NAT_T_DRAFT02N: [u8; 16] = *b"\x90\xcb\x80\x91\x3e\xbb\x69\x6e\x08\x63\x81\xb5\xec\x42\x7b\x1f";
    /// MD5("draft-ietf-ipsec-nat-t-ike-03").
    pub const NAT_T_DRAFT03: [u8; 16] = *b"\x7d\x94\x19\xa6\x53\x10\xca\x6f\x2c\x17\x9d\x92\x15\x52\x9d\x56";
    pub const XAUTH: [u8; 8] = *b"\x09\x00\x26\x89\xdf\xd6\xb7\x12";
    /// RFC 3706 (major 1, minor 0).
    pub const DPD: [u8; 16] = *b"\xaf\xca\xd7\x13\x68\xa1\xf1\xc9\x6b\x86\x96\xfc\x77\x57\x01\x00";
    pub const CISCO_UNITY: [u8; 16] = *b"\x12\xf5\xf2\x8c\x45\x71\x68\xa9\x70\x2d\x9f\xe2\x74\xcc\x01\x00";
}
