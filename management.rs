use crate::common::{MACCommon, parse_ies, Ie, serialize_ies};

pub enum MgmtSubType {
    AssocRequest(AssocRequestFrame),        //0000
    AssocResponse(AssocResponseFrame),      //0001
    ProbeRequest(ProbeRequestFrame),        //0100
    ProbeResponse(ProbeResponseFrame),      //0101
    Beacon(BeaconFrame),                    //1000
    Authentication(AuthenticationFrame),    //1011
}

impl MgmtSubType {
    pub fn parse(common: MACCommon, body: &[u8]) -> Option<Self> {
        if body.len() < 24 {
            return None;
        }

        let header: MgmtHeader = MgmtHeader {
            common,
            addr1: body[0..6].try_into().unwrap(),
            addr2: body[6..12].try_into().unwrap(),
            addr3: body[12..18].try_into().unwrap(),
            seq_ctrl: u16::from_le_bytes([body[18], body[19]]),
        };

        let subtype: u8 = common.frame_control.subtype();

        if common.frame_control.to_ds() || common.frame_control.from_ds() {
            return None;
        }

        match subtype {
            0b0000 => parse_assoc_request(header, &body[20..]),
            0b0001 => parse_assoc_response(header, &body[20..]),
            0b0100 => parse_probe_request(header, &body[20..]),
            0b0101 => parse_probe_response(header, &body[20..]),
            0b1000 => parse_beacon(header, &body[20..]),
            0b1011 => parse_authentication(header, &body[20..]),
            _ => {
                panic!("Unimplemented management subtype: {:04b}", subtype);
            }
        }
    }

    pub fn serialize(&self, out: &mut Vec<u8>) {
        match self {
            MgmtSubType::AssocRequest(f) => f.serialize(out),
            MgmtSubType::AssocResponse(f) => f.serialize(out),
            MgmtSubType::ProbeRequest(f) => f.serialize(out),
            MgmtSubType::ProbeResponse(f) => f.serialize(out),
            MgmtSubType::Beacon(f) => f.serialize(out),
            MgmtSubType::Authentication(f) => f.serialize(out),
        }
    }

    pub fn header(&self) -> &MgmtHeader {
        match self {
            MgmtSubType::AssocRequest(f) => &f.header,
            MgmtSubType::AssocResponse(f) => &f.header,
            MgmtSubType::ProbeRequest(f) => &f.header,
            MgmtSubType::ProbeResponse(f) => &f.header,
            MgmtSubType::Beacon(f) => &f.header,
            MgmtSubType::Authentication(f) => &f.header,
        }
    }
}

pub struct MgmtHeader {
    pub common: MACCommon,
    pub addr1: [u8; 6],
    pub addr2: [u8; 6],
    pub addr3: [u8; 6],
    pub seq_ctrl: u16,
}

pub struct AssocRequestFrame {
    pub header: MgmtHeader,
    pub capability_info: u16,
    pub listen_interval: u16,
    pub ie_storage: Vec<u8>,
    // pub ies: Vec<Ie<'a>>,
}

impl AssocRequestFrame {
    pub fn serialize(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.header.common.frame_control.0.to_le_bytes());
        out.extend_from_slice(&self.header.common.duration.to_le_bytes());

        out.extend_from_slice(&self.header.addr1);
        out.extend_from_slice(&self.header.addr2);
        out.extend_from_slice(&self.header.addr3);

        out.extend_from_slice(&self.header.seq_ctrl.to_le_bytes());

        out.extend_from_slice(&self.capability_info.to_le_bytes());
        out.extend_from_slice(&self.listen_interval.to_le_bytes());
        out.extend_from_slice(self.ie_storage.as_slice());
        // serialize_ies(&self.ies, out)
    }
}

fn parse_assoc_request<'a>(header: MgmtHeader, body: &'a [u8]) -> Option<MgmtSubType> {
    if body.len() < 4 {
        return None;
    }

    let capability_info: u16 = u16::from_le_bytes([body[0], body[1]]);
    let listen_interval: u16 = u16::from_le_bytes([body[2], body[3]]);

    Some(MgmtSubType::AssocRequest(AssocRequestFrame {
        header,
        capability_info,
        listen_interval,
        ie_storage: body[4..].to_vec(),
        // ies: parse_ies(&body[4..]),
    }))
}

pub struct AssocResponseFrame {
    pub header: MgmtHeader,
    pub capability_info: u16,
    pub status_code: u16,
    pub aid: u16,
    pub ie_storage: Vec<u8>,
    // pub ies: Vec<Ie<'a>>,
}

impl AssocResponseFrame {
    pub fn serialize(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.header.common.frame_control.0.to_le_bytes());
        out.extend_from_slice(&self.header.common.duration.to_le_bytes());

        out.extend_from_slice(&self.header.addr1);
        out.extend_from_slice(&self.header.addr2);
        out.extend_from_slice(&self.header.addr3);

        out.extend_from_slice(&self.header.seq_ctrl.to_le_bytes());

        out.extend_from_slice(&self.capability_info.to_le_bytes());
        out.extend_from_slice(&self.status_code.to_le_bytes());
        out.extend_from_slice(&(&self.aid | (0b11u16 << 14)).to_le_bytes());
        out.extend_from_slice(self.ie_storage.as_slice());
        // serialize_ies(&self.ies, out)
    }
}

fn parse_assoc_response(header: MgmtHeader, body: &[u8]) -> Option<MgmtSubType> {
    if body.len() < 6 {
        return None;
    }

    let capability_info: u16 = u16::from_le_bytes([body[0], body[1]]);
    let status_code: u16 = u16::from_le_bytes([body[2], body[3]]);
    let aid: u16 = u16::from_le_bytes([body[4], body[5]]) & 0x3FFF;

    Some(MgmtSubType::AssocResponse(AssocResponseFrame {
        header,
        capability_info,
        status_code,
        aid,
        ie_storage: body[6..].to_vec(),
        // ies: parse_ies(&body[6..]),
    }))
}

pub struct ProbeRequestFrame {
    pub header: MgmtHeader,
    pub ie_storage: Vec<u8>,
    // pub ies: Vec<Ie<'a>>,
}

impl ProbeRequestFrame {
    pub fn serialize(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.header.common.frame_control.0.to_le_bytes());
        out.extend_from_slice(&self.header.common.duration.to_le_bytes());

        out.extend_from_slice(&self.header.addr1);
        out.extend_from_slice(&self.header.addr2);
        out.extend_from_slice(&self.header.addr3);

        out.extend_from_slice(&self.header.seq_ctrl.to_le_bytes());

        out.extend_from_slice(self.ie_storage.as_slice());
        // serialize_ies(&self.ies, out)
    }
}

fn parse_probe_request(header: MgmtHeader, body: &[u8]) -> Option<MgmtSubType> {
    Some(MgmtSubType::ProbeRequest(ProbeRequestFrame {
        header,
        ie_storage: body.to_vec(),
        // ies: parse_ies(&body[0..])
    }))
}

pub struct ProbeResponseFrame {
    pub header: MgmtHeader,
    pub timestamp: u64,
    pub beacon_interval: u16,
    pub capability_info: u16,
    pub ie_storage: Vec<u8>,
    // pub ies: Vec<Ie<'a>>,
}

impl ProbeResponseFrame {
    pub fn serialize(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.header.common.frame_control.0.to_le_bytes());
        out.extend_from_slice(&self.header.common.duration.to_le_bytes());

        out.extend_from_slice(&self.header.addr1);
        out.extend_from_slice(&self.header.addr2);
        out.extend_from_slice(&self.header.addr3);

        out.extend_from_slice(&self.header.seq_ctrl.to_le_bytes());

        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.extend_from_slice(&self.beacon_interval.to_le_bytes());
        out.extend_from_slice(&self.capability_info.to_le_bytes());
        out.extend_from_slice(self.ie_storage.as_slice());
        // serialize_ies(&self.ies, out)
    }
}

fn parse_probe_response<'a>(header: MgmtHeader, body: &'a [u8]) -> Option<MgmtSubType> {
    if body.len() < 12 {
        return None;
    }

    let timestamp: u64 = u64::from_le_bytes([body[0], body[1], body[2], body[3], body[4], body[5], body[6], body[7]]);
    let beacon_interval: u16 = u16::from_le_bytes([body[8], body[9]]);
    let capability_info: u16 = u16::from_le_bytes([body[10], body[11]]);

    Some(MgmtSubType::ProbeResponse(ProbeResponseFrame {
        header,
        timestamp,
        beacon_interval,
        capability_info,
        ie_storage: body[12..].to_vec(),
        // ies: parse_ies(&body[12..]),
    }))
}

pub struct BeaconFrame {
    pub header: MgmtHeader,
    pub timestamp: u64,
    pub beacon_interval: u16,
    pub capability_info: u16,
    pub ie_storage: Vec<u8>,
    // pub ies: Vec<Ie<'a>>,
}

impl BeaconFrame {
    pub fn serialize(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.header.common.frame_control.0.to_le_bytes());
        out.extend_from_slice(&self.header.common.duration.to_le_bytes());

        out.extend_from_slice(&self.header.addr1);
        out.extend_from_slice(&self.header.addr2);
        out.extend_from_slice(&self.header.addr3);

        out.extend_from_slice(&self.header.seq_ctrl.to_le_bytes());

        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.extend_from_slice(&self.beacon_interval.to_le_bytes());
        out.extend_from_slice(&self.capability_info.to_le_bytes());
        out.extend_from_slice(self.ie_storage.as_slice());
        // serialize_ies(&self.ies, out)
    }
}

fn parse_beacon<'a>(header: MgmtHeader, body: &'a [u8]) -> Option<MgmtSubType> {
    if body.len() < 12 {
        return None;
    }

    let timestamp: u64 = u64::from_le_bytes([body[0], body[1], body[2], body[3], body[4], body[5], body[6], body[7]]);
    let beacon_interval: u16 = u16::from_le_bytes([body[8], body[9]]);
    let capability_info: u16 = u16::from_le_bytes([body[10], body[11]]);

    Some(MgmtSubType::Beacon(BeaconFrame {
        header,
        timestamp,
        beacon_interval,
        capability_info,
        ie_storage: body[12..].to_vec(),
        // ies: parse_ies(&body[12..]),
    }))
}

pub struct AuthenticationFrame {
    pub header: MgmtHeader,
    pub auth_algorithm: u16,
    pub auth_seq: u16,
    pub status_code: u16,
    pub body: Vec<u8>,
}

impl AuthenticationFrame {
    pub fn serialize(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.header.common.frame_control.0.to_le_bytes());
        out.extend_from_slice(&self.header.common.duration.to_le_bytes());

        out.extend_from_slice(&self.header.addr1);
        out.extend_from_slice(&self.header.addr2);
        out.extend_from_slice(&self.header.addr3);

        out.extend_from_slice(&self.header.seq_ctrl.to_le_bytes());

        out.extend_from_slice(&self.auth_algorithm.to_le_bytes());
        out.extend_from_slice(&self.auth_seq.to_le_bytes());
        out.extend_from_slice(&self.status_code.to_le_bytes());
        
        out.extend_from_slice(&self.body);
    }
}

fn parse_authentication<'a>(header: MgmtHeader, body: &'a [u8]) -> Option<MgmtSubType> {
    if body.len() < 6 {
        return None;
    }

    let auth_algorithm: u16 = u16::from_le_bytes([body[0], body[1]]);
    let auth_seq: u16 = u16::from_le_bytes([body[2], body[3]]);
    let status_code: u16 = u16::from_le_bytes([body[4], body[5]]);

    Some(MgmtSubType::Authentication(AuthenticationFrame {
        header,
        auth_algorithm,
        auth_seq,
        status_code,
        body: body[6..].to_vec(),
    }))
}