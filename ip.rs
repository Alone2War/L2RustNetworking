

pub enum L3Packet {
    Ipv4(Vec<u8>),
    Ipv6(Vec<u8>),
    Arp(Vec<u8>),
    Eapol(Vec<u8>),
    EapolKey(EapolKeyFrame),
    Unknown(u16, Vec<u8>),
}

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;
pub const ETHERTYPE_ARP:  u16 = 0x0806;
pub const ETHERTYPE_EAPOL: u16 = 0x888E;

impl L3Packet {
    pub fn bytes(&self, out: &mut Vec<u8>) {
        out.clear();
        match self {
            L3Packet::Ipv4(b)
            | L3Packet::Ipv6(b)
            | L3Packet::Arp(b)
            | L3Packet::Eapol(b)
            | L3Packet::Unknown(_, b) => {
                out.extend_from_slice(b);
            },

            L3Packet::EapolKey(k) => {
                k.serialize(out);
            }
        }
    }

    pub fn ethertype(&self) -> u16 {
        match self {
            L3Packet::Ipv4(_) => ETHERTYPE_IPV4,
            L3Packet::Ipv6(_) => ETHERTYPE_IPV6,
            L3Packet::Arp(_)  => ETHERTYPE_ARP,
            L3Packet::Eapol(_) => ETHERTYPE_EAPOL,
            L3Packet::EapolKey(_) => ETHERTYPE_EAPOL,
            L3Packet::Unknown(t, _) => *t,
        }
    }
}

#[derive(Clone)]
pub struct EapolHeader {
    pub version: u8,
    pub packet_type: u8,
    pub length: u16,
}

#[derive(Clone)]
pub struct EapolKeyFrame {
    pub header: EapolHeader,
    pub descriptor_type: u8,
    pub key_info: u16,
    pub key_length: u16,
    pub replay_counter: u64,
    pub key_nonce: [u8; 32],
    pub key_iv: [u8; 16],
    pub key_rsc: [u8; 8],
    pub key_id: [u8; 8],
    pub key_mic: [u8; 16],
    pub key_data_len: u16,
    pub key_data: Vec<u8>,
}

impl EapolKeyFrame {
    pub fn is_pairwise(&self) -> bool { self.key_info & (1 << 3) != 0 }
    pub fn has_install(&self) -> bool { self.key_info & (1 << 6) != 0 }
    pub fn has_ack(&self) -> bool     { self.key_info & (1 << 7) != 0 }
    pub fn has_mic(&self) -> bool     { self.key_info & (1 << 8) != 0 }
    pub fn has_secure(&self) -> bool  { self.key_info & (1 << 9) != 0 }

    pub fn is_msg1(&self) -> bool {
        self.is_pairwise() && self.has_ack() && !self.has_mic() && !self.has_install() && !self.has_secure()
    }
    pub fn is_msg2(&self) -> bool {
        self.is_pairwise() && self.has_mic() && !self.has_ack() && !self.has_install() && !self.has_secure()
    }
    pub fn is_msg3(&self) -> bool {
        self.is_pairwise() && self.has_mic() && self.has_ack() && self.has_install() && self.has_secure()
    }
    pub fn is_msg4(&self) -> bool {
        self.is_pairwise() && self.has_mic() && !self.has_ack() && !self.has_install() && self.has_secure()
    }

    pub fn serialize(&self, out: &mut Vec<u8>) {
        out.clear();

        let body_len = 95 + self.key_data.len() as usize;

        out.push(self.header.version);
        out.push(self.header.packet_type);
        out.extend_from_slice(&(body_len as u16).to_be_bytes());

        out.push(self.descriptor_type);
        out.extend_from_slice(&self.key_info.to_be_bytes());
        out.extend_from_slice(&self.key_length.to_be_bytes());
        out.extend_from_slice(&self.replay_counter.to_be_bytes());
        out.extend_from_slice(&self.key_nonce);
        out.extend_from_slice(&self.key_iv);
        out.extend_from_slice(&self.key_rsc);
        out.extend_from_slice(&self.key_id);
        out.extend_from_slice(&self.key_mic);
        out.extend_from_slice(&self.key_data_len.to_be_bytes());
        out.extend_from_slice(self.key_data.as_slice());
    }
}

pub fn is_valid_ipv4(bytes: &[u8]) -> bool {
    if bytes.len() < 20 {
        return false;
    }
    let version = bytes[0] >> 4;
    version == 4
}

pub fn is_valid_ipv6(bytes: &[u8]) -> bool {
    if bytes.len() < 40 {
        return false;
    }
    let version = bytes[0] >> 4;
    version == 6
}

fn parse_eapol_key<'a>(bytes: &'a [u8]) -> Option<EapolKeyFrame> {
    if bytes.len() < 4 { return None; }

    let version = bytes[0];
    let packet_type = bytes[1];
    let length = u16::from_be_bytes([bytes[2], bytes[3]]);

    let header = EapolHeader {
        version,
        packet_type,
        length,
    };

    if packet_type != 3 { return None; }

    let body = &bytes[4..];
    if length < 95 { return None; }
    if body.len() < length as usize { return None; }
    if body.len() < 95 { return None; }

    let descriptor_type = body[0];
    let key_info = u16::from_be_bytes([body[1], body[2]]);
    let key_length = u16::from_be_bytes([body[3], body[4]]);
    let replay_counter = u64::from_be_bytes([body[5], body[6], body[7], body[8], body[9], body[10], body[11], body[12]]);
    let mut key_nonce = [0u8; 32]; key_nonce.copy_from_slice(&body[13..45]);
    let mut key_iv = [0u8; 16]; key_iv.copy_from_slice(&body[45..61]);
    let mut key_rsc = [0u8; 8]; key_rsc.copy_from_slice(&body[61..69]);
    let mut key_id = [0u8; 8]; key_id.copy_from_slice(&body[69..77]);
    let mut key_mic = [0u8; 16]; key_mic.copy_from_slice(&body[77..93]);
    let key_data_len = u16::from_be_bytes([body[93], body[94]]);

    if body.len() < 95 + key_data_len as usize { return None; }
    let key_data = &body[95 .. 95 + key_data_len as usize];

    Some(EapolKeyFrame {
        header,
        descriptor_type,
        key_info,
        key_length,
        replay_counter,
        key_nonce,
        key_iv,
        key_rsc,
        key_id,
        key_mic,
        key_data_len,
        key_data: key_data.to_vec(),
    })
}

pub fn parse_l3<'a>(payload: &'a [u8]) -> Option<L3Packet> {
    if payload.len() < 8 {
        return None;
    }

    let llc = &payload[0..3];
    if llc != [0xAA, 0xAA, 0x03] {
        return None;
    }

    let oui = &payload[3..6];
    if oui != [0x00, 0x00, 0x00] {
        return None;
    }

    let ethertype = u16::from_be_bytes([payload[6], payload[7]]);
    let l3 = &payload[8..];

    match ethertype {
        ETHERTYPE_IPV4 => {
            if is_valid_ipv4(l3) {
                Some(L3Packet::Ipv4(l3.to_vec()))
            } else {
                None
            }
        }

        ETHERTYPE_IPV6 => {
            if is_valid_ipv6(l3) {
                Some(L3Packet::Ipv6(l3.to_vec()))
            } else {
                None
            }
        }

        ETHERTYPE_ARP => Some(L3Packet::Arp(l3.to_vec())),
        ETHERTYPE_EAPOL => {
            if let Some(key) = parse_eapol_key(l3) {
                Some(L3Packet::EapolKey(key))
            } else {
                Some(L3Packet::Eapol(l3.to_vec()))
            }
        }, // Some(L3Packet::Eapol(l3)),

        other => Some(L3Packet::Unknown(other, l3.to_vec())),
    }
}