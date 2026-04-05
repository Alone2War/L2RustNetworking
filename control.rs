use crate::common::MACCommon;

pub enum CtrlSubType {
    Ack(AckFrame),  //1101
}

impl CtrlSubType {
    pub fn parse(common: MACCommon, body: &[u8]) -> Option<Self> {
        if body.len() < 6 {
            return None;
        }

        let header: CtrlHeader = CtrlHeader {
            common,
            addr1: body[0..6].try_into().unwrap(),
        };

        let subtype: u8 = common.frame_control.subtype();

        if common.frame_control.to_ds() || common.frame_control.from_ds() {
            return None;
        }

        match subtype {
            0b1101 => parse_ack(header),
            _ => {
                panic!("Unimplemented control subtype: {:04b}", subtype);
            }
        }
    }

    pub fn serialize(&self, out: &mut Vec<u8>) {
        match self {
            CtrlSubType::Ack(f) => f.serialize(out),
        }
    }
}

pub struct CtrlHeader {
    pub common: MACCommon,
    pub addr1: [u8; 6],
}

pub struct AckFrame {
    pub header: CtrlHeader,
}

impl AckFrame {
    pub fn serialize(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.header.common.frame_control.0.to_le_bytes());
        out.extend_from_slice(&self.header.common.duration.to_le_bytes());

        out.extend_from_slice(&self.header.addr1);
    }
}

fn parse_ack(header: CtrlHeader) -> Option<CtrlSubType> {
    Some(CtrlSubType::Ack(AckFrame {
        header,
    }))
}