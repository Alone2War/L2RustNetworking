use crate::common::MACCommon;
use crate::ip::L3Packet;

pub enum DataSubType {
    Data(DataFrame), //0000
}

impl DataSubType {
    pub fn parse(common: MACCommon, body: &[u8]) -> Option<Self> {
        let marker: usize;

        let header: DataHeader = 
        if common.frame_control.to_ds() && common.frame_control.from_ds() {
            if body.len() < 26 {
                return None;
            }

            marker = 26;
            DataHeader::FourAddr {
                common,
                addr1: body[0..6].try_into().unwrap(),
                addr2: body[6..12].try_into().unwrap(),
                addr3: body[12..18].try_into().unwrap(),
                addr4: body[18..24].try_into().unwrap(),
                seq_ctrl: u16::from_le_bytes([body[24], body[25]]),
            }
        }else{
            if body.len() < 20 {
                return None;
            }

            marker = 20;
            DataHeader::ThreeAddr {
                common,
                addr1: body[0..6].try_into().unwrap(),
                addr2: body[6..12].try_into().unwrap(),
                addr3: body[12..18].try_into().unwrap(),
                seq_ctrl: u16::from_le_bytes([body[18], body[19]]),
            }
        };

        let subtype: u8 = common.frame_control.subtype();

        match subtype {
            0b0000 => parse_data(header, &body[marker..]),
            _ => {
                panic!("Unimplemented data subtype: {:04b}", subtype);
            }
        }
    }

    pub fn serialize(&self, out: &mut Vec<u8>) {
        match self {
            DataSubType::Data(f) => f.serialize(out),
        }
    }

    pub fn header(&self) -> &DataHeader {
        match self {
            DataSubType::Data(f) => &f.header,
        }
    }
}

//pub struct DataHeader {
//    pub common: MACCommon,
//    pub addr1: [u8; 6],
//    pub addr2: [u8; 6],
//    pub addr3: [u8; 6],
//    pub seq_ctrl: u16,
//}

pub enum DataHeader {
    ThreeAddr {
        common: MACCommon,
        addr1: [u8; 6],
        addr2: [u8; 6],
        addr3: [u8; 6],
        seq_ctrl: u16,
    },
    FourAddr {
        common: MACCommon,
        addr1: [u8; 6],
        addr2: [u8; 6],
        addr3: [u8; 6],
        addr4: [u8; 6],
        seq_ctrl: u16,
    },
}

pub struct DataFrame {
    pub header: DataHeader,
    pub payload: Vec<u8>,
}

fn parse_data<'a>(header: DataHeader, body: &'a [u8]) -> Option<DataSubType> {
    Some(DataSubType::Data(DataFrame {
        header,
        payload: body.to_vec(),
    }))
}

pub fn build_llc_snap<'a>(ethertype: u16, l3_bytes: Vec<u8>, out: &'a mut Vec<u8>) -> &'a [u8] {
    out.clear();

    out.extend_from_slice(&[0xAA, 0xAA, 0x03]);
    out.extend_from_slice(&[0x00, 0x00, 0x00]);
    out.extend_from_slice(&ethertype.to_be_bytes());
    out.extend_from_slice(l3_bytes.as_slice());

    out.as_slice()
}

impl DataFrame {
    pub fn l3_parse(&self) -> Option<L3Packet> {
        crate::ip::parse_l3(&self.payload)
    }

    pub fn from_l3(
        header: DataHeader,
        l3: L3Packet,
        mut buf: Vec<u8>,
    ) -> Self {
        let mut bytes: Vec<u8> = Vec::new(); l3.bytes(&mut bytes);
        let payload_slice = build_llc_snap(l3.ethertype(), bytes, &mut buf);

        DataFrame {
            header,
            payload: payload_slice.to_vec(),
        }
    }

    pub fn from_l3_parts(
        common: MACCommon,
        addr1: [u8; 6],
        addr2: [u8; 6],
        addr3: [u8; 6],
        seq_ctrl: u16,
        l3: L3Packet,
        buf: Vec<u8>,
    ) -> Self {
        let header: DataHeader = DataHeader::ThreeAddr {
            common,
            addr1,
            addr2,
            addr3,
            seq_ctrl,
        };

        DataFrame::from_l3(header, l3, buf)
    }

    pub fn serialize(&self, out: &mut Vec<u8>) {
        match &self.header {
            DataHeader::ThreeAddr {
                common,
                addr1,
                addr2,
                addr3,
                seq_ctrl,
            } => {
                out.extend_from_slice(&common.frame_control.0.to_le_bytes());
                out.extend_from_slice(&common.duration.to_le_bytes());
                out.extend_from_slice(addr1);
                out.extend_from_slice(addr2);
                out.extend_from_slice(addr3);
                out.extend_from_slice(&seq_ctrl.to_le_bytes());
            }

            DataHeader::FourAddr {
                common,
                addr1,
                addr2,
                addr3,
                addr4,
                seq_ctrl,
            } => {
                out.extend_from_slice(&common.frame_control.0.to_le_bytes());
                out.extend_from_slice(&common.duration.to_le_bytes());
                out.extend_from_slice(addr1);
                out.extend_from_slice(addr2);
                out.extend_from_slice(addr3);
                out.extend_from_slice(addr4);
                out.extend_from_slice(&seq_ctrl.to_le_bytes());
            }
        }

        out.extend_from_slice(&self.payload);
    }
}