use crate::management::MgmtSubType;
use crate::control::CtrlSubType;
use crate::data::DataSubType;

pub struct PHY {
    pub frame: Vec<u8>,
}

#[derive(Copy, Clone)]
pub struct FrameControl(pub(crate) u16);

impl FrameControl {
    pub fn frame_type(&self) -> u8 { ((self.0 >> 2) & 0b11) as u8 }
    pub fn subtype(&self) -> u8 { ((self.0 >> 4) & 0b1111) as u8 }
    pub fn to_ds(&self) -> bool { (self.0 & (1 << 8)) != 0 }
    pub fn from_ds(&self) -> bool { (self.0 & (1 << 9)) != 0 }
}

#[derive(Copy, Clone)]
pub struct MACCommon {
    pub frame_control: FrameControl,
    pub duration: u16,
}
//Frame Control:
//  Protocol Version: 2 bits: Always 00
//  Type: 2 bits: 00 management, 01 control, 10 data
//  Subtype: 4 bits: Different per type, defined in each file

pub enum FrameType {
    Management(MgmtSubType),
    Control(CtrlSubType),
    Data(DataSubType),
}

impl PHY {
    pub fn parse(&self) -> Option<FrameType> {
        if self.frame.len() < 4 {
            return None;
        }

        let frame_control: FrameControl = FrameControl(u16::from_le_bytes([self.frame[0], self.frame[1]]));
        let duration: u16 = u16::from_le_bytes([self.frame[2], self.frame[3]]);

        let mac: MACCommon = MACCommon {
            frame_control,
            duration,
        };

        FrameType::parse(mac, &self.frame[4..])
    }

    pub fn from_mac(mac_bytes: &Vec<u8>) -> Self {
        PHY {frame: mac_bytes.to_vec()}
    }
}

impl FrameType {
    pub fn parse(common: MACCommon, body: &[u8]) -> Option<Self> {
        let frame_type: u8 = common.frame_control.frame_type();

        match frame_type {
            0b00 => MgmtSubType::parse(common, body).map(FrameType::Management),
            0b01 => CtrlSubType::parse(common, body).map(FrameType::Control),
            0b10 => DataSubType::parse(common, body).map(FrameType::Data),
            _ => None,
        }
    }
    pub fn serialize(&self, out: &mut Vec<u8>) {
        out.clear();

        match self {
            FrameType::Management(m) => m.serialize(out),
            FrameType::Control(c) => c.serialize(out),
            FrameType::Data(d) => d.serialize(out),
        }
    }
}

#[derive(Copy, Clone)]
pub struct Ie<'a> {
    pub id: u8,
    pub value: &'a [u8],
}

pub fn parse_ies<'a>(mut bytes: &'a [u8]) -> Vec<Ie<'a>> {
    let mut ies: Vec<Ie<'a>> = Vec::new();

    while bytes.len() >= 2 {
        let id: u8 = bytes[0];
        let len: usize = bytes[1] as usize;

        if bytes.len() < 2 + len {
            break;
        }

        let value: &[u8] = &bytes[2 .. 2 + len];
        ies.push(Ie {id, value});

        bytes = &bytes[2 + len ..];
    }

    ies
}

pub fn serialize_ies<'a>(ies: &Vec<Ie<'a>>, out: &mut Vec<u8>) {
    for ie in ies {
        out.push(ie.id);
        out.push(ie.value.len() as u8);
        out.extend_from_slice(ie.value);
    }
}