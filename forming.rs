pub mod forming {
    use crate::common::*;

    struct FrameControlParams {
        protocol: u16,
        ftype: u16,
        subtype: u16,
        to_ds: bool,
        from_ds: bool,
        more_fragments: bool,
        retry: bool,
        pwr_mgmt: bool,
        more_data: bool,
        prot_frame: bool,
        phtc_order: bool,
    }

    impl FrameControlParams {
        fn new(ftype: u16, subtype: u16) -> Self {
            Self {
                protocol: 0,
                ftype,
                subtype,
                to_ds: false,
                from_ds: false,
                more_fragments: false,
                retry: false,
                pwr_mgmt: false,
                more_data: false,
                prot_frame: false,
                phtc_order: false,
            }
        }

        fn apply_if(self, cond: bool, f: impl FnOnce(Self) -> Self) -> Self {
            if cond { f(self) } else { self }
        }

        fn mgmt(subtype: u16) -> Self { Self::new(0b00u16, subtype) }
        fn ctrl(subtype: u16) -> Self { Self::new(0b01u16, subtype) }
        fn data(subtype: u16) -> Self { Self::new(0b10u16, subtype) }

        fn probe_request() -> Self { Self::mgmt(0b0100u16) }
        fn probe_response() -> Self { Self::mgmt(0b0101u16) }
        fn authentication() -> Self { Self::mgmt(0b1011u16) }
        fn association_request() -> Self { Self::mgmt(0b0000u16) }
        fn association_response() -> Self { Self::mgmt(0b0001u16) }
        fn beacon() -> Self { Self::mgmt(0b1000u16) }

        fn ack() -> Self { Self::ctrl(0b1101u16) }

        fn dataframe() -> Self { Self::data(0b0000u16) }

        fn to_ds(mut self) -> Self { self.to_ds = true; self }
        fn from_ds(mut self) -> Self { self.from_ds = true; self }

        fn form(self) -> FrameControl {
            let mut fc: u16 = 0;

            fc |= (self.protocol & 0b11) << 0;
            fc |= (self.ftype & 0b11) << 2;
            fc |= (self.subtype & 0b1111) << 4;
            fc |= (self.to_ds as u16) << 8;
            fc |= (self.from_ds as u16) << 9;
            fc |= (self.more_fragments as u16) << 10;
            fc |= (self.retry as u16) << 11;
            fc |= (self.pwr_mgmt as u16) << 12;
            fc |= (self.more_data as u16) << 13;
            fc |= (self.prot_frame as u16) << 14;
            fc |= (self.phtc_order as u16) << 15;

            FrameControl(fc)
        }
    }

    pub mod management {
        use crate::common::*;
        use crate::management::*;
        use crate::forming::forming::FrameControlParams;

        pub fn probe_request(
            src: [u8; 6],
            seq: u16,
            ie_storage: &[u8],
        ) -> MgmtSubType {
            let fc = FrameControlParams::probe_request().form();
            let common = MACCommon {frame_control: fc, duration: 0};

            let header = MgmtHeader {
                common,
                addr1: [0xff; 6],
                addr2: src,
                addr3: [0xff; 6],
                seq_ctrl: seq,
            };

            MgmtSubType::ProbeRequest(ProbeRequestFrame {header, ie_storage: ie_storage.to_vec()})
        }

        pub fn probe_response(
            dst: [u8; 6],
            src: [u8; 6],
            bssid: [u8; 6],
            seq: u16,
            timestamp: u64,
            beacon_interval: u16,
            capability_info: u16,
            ie_storage: &[u8],
            // ies: Vec<Ie<'a>>,
        ) -> MgmtSubType {
            let fc = FrameControlParams::probe_response().form();
            let common = MACCommon {frame_control: fc, duration: 0};

            let header = MgmtHeader {
                common,
                addr1: dst,
                addr2: src,
                addr3: bssid,
                seq_ctrl: seq,
            };

            MgmtSubType::ProbeResponse(ProbeResponseFrame {
                header,
                timestamp,
                beacon_interval,
                capability_info,
                ie_storage: ie_storage.to_vec(),
            })
        }

        pub fn authentication(
            dst: [u8; 6],
            src: [u8; 6],
            bssid: [u8; 6],
            seq: u16,
            auth_seq: u16,
            status_code: u16,
            body: &[u8],
        ) -> MgmtSubType {
            let fc = FrameControlParams::authentication().form();
            let common = MACCommon {frame_control: fc, duration: 0};

            let header = MgmtHeader {
                common,
                addr1: dst,
                addr2: src,
                addr3: bssid,
                seq_ctrl: seq,
            };

            MgmtSubType::Authentication(AuthenticationFrame {
                header,
                auth_algorithm: 0,
                auth_seq,
                status_code,
                body: body.to_vec(),
            })
        }

        pub fn association_request(
            dst: [u8; 6],
            src: [u8; 6],
            bssid: [u8; 6],
            seq: u16,
            capability_info: u16,
            listen_interval: u16,
            ie_storage: &[u8],
            //ies: Vec<Ie<'a>>,
        ) -> MgmtSubType {
            let fc = FrameControlParams::association_request().form();
            let common = MACCommon {frame_control: fc, duration: 0};

            let header = MgmtHeader {
                common,
                addr1: dst,
                addr2: src,
                addr3: bssid,
                seq_ctrl: seq,
            };

            MgmtSubType::AssocRequest(AssocRequestFrame {
                header,
                capability_info,
                listen_interval,
                ie_storage: ie_storage.to_vec(),
            })
        }

        pub fn association_response(
            dst: [u8; 6],
            src: [u8; 6],
            bssid: [u8; 6],
            seq: u16,
            capability_info: u16,
            status_code: u16,
            aid: u16,
            ie_storage: &[u8],
            // ies: Vec<Ie<'a>>,
        ) -> MgmtSubType {
            let fc = FrameControlParams::association_response().form();
            let common = MACCommon {frame_control: fc, duration: 0};

            let header = MgmtHeader {
                common,
                addr1: dst,
                addr2: src,
                addr3: bssid,
                seq_ctrl: seq,
            };

            MgmtSubType::AssocResponse(AssocResponseFrame {
                header,
                capability_info,
                status_code,
                aid,
                ie_storage: ie_storage.to_vec(),
            })
        }

        pub fn beacon(
            dst: [u8; 6], // usually [0xff; 6]
            src: [u8; 6],
            bssid: [u8; 6],
            seq: u16,
            timestamp: u64,
            beacon_interval: u16,
            capability_info: u16,
            ie_storage: &[u8],
            // ies: Vec<Ie<'a>>,
        ) -> MgmtSubType {
            let fc = FrameControlParams::beacon().form();
            let common = MACCommon {frame_control: fc, duration: 0};

            let header = MgmtHeader {
                common,
                addr1: dst,
                addr2: src,
                addr3: bssid, //bssid
                seq_ctrl: seq,
            };

            MgmtSubType::Beacon(BeaconFrame {
                header,
                timestamp,
                beacon_interval,
                capability_info,
                ie_storage: ie_storage.to_vec(),
            })
        }
    }

    pub mod ctrl {
        use crate::common::*;
        use crate::control::*;
        use crate::forming::forming::FrameControlParams;

        pub fn ack(
            dst: [u8; 6],
        ) -> CtrlSubType {
            let fc = FrameControlParams::ack().form();
            let common = MACCommon {frame_control: fc, duration: 0};

            let header = CtrlHeader {
                common,
                addr1: dst,
            };

            CtrlSubType::Ack(AckFrame {
                header,
            })
        }
    }

    pub mod data {
        use crate::common::*;
        use crate::data::*;
        use crate::forming::forming::FrameControlParams;

        pub fn data<'a>(
            dst: [u8; 6],
            src: [u8; 6],
            bssid: [u8; 6],
            seq: u16,
            to_ds: bool,
            from_ds: bool,
            payload: &'a [u8],
        ) -> DataSubType {
            let fc = FrameControlParams::dataframe()
                .apply_if(to_ds, FrameControlParams::to_ds)
                .apply_if(from_ds, FrameControlParams::from_ds)
                .form();
            let common = MACCommon {frame_control: fc, duration: 0};

            let header = DataHeader::ThreeAddr {
                common,
                addr1: dst,
                addr2: src,
                addr3: bssid,
                seq_ctrl: seq,
            };

            DataSubType::Data(DataFrame {
                header,
                payload: payload.to_vec(),
            })
        }

        pub fn data_wds<'a>(
            ra: [u8; 6],
            ta: [u8; 6],
            da: [u8; 6],
            sa: [u8; 6],
            seq: u16,
            payload: &'a [u8],
        ) -> DataSubType {
            let fc = FrameControlParams::dataframe()
                .to_ds()
                .from_ds()
                .form();
            let common = MACCommon {frame_control: fc, duration: 0};

            let header = DataHeader::FourAddr {
                common,
                addr1: ra,
                addr2: ta,
                addr3: da,
                addr4: sa,
                seq_ctrl: seq,
            };

            DataSubType::Data(DataFrame {
                header,
                payload: payload.to_vec(),
            })
        }
    }
    pub mod Eapol {
        use crate::ip::*;
        use crate::forming::*;
        use crate::data::*;

        pub fn Eapol_build_msg1<'a>(
            anonce: &[u8; 32],
            replay: u64,
        ) -> EapolKeyFrame {
            EapolKeyFrame {
                header: EapolHeader {
                    version: 2,
                    packet_type: 3,
                    length: 0, //determined at serialization
                },
                descriptor_type: 2,
                key_info: (1 << 3) | (1 << 7),
                key_length: 16,
                replay_counter: replay,
                key_nonce: *anonce,
                key_iv: [0u8; 16],
                key_rsc: [0u8; 8],
                key_id: [0u8; 8],
                key_mic: [0u8; 16],
                key_data_len: 0,
                key_data: Vec::new(),
            }
        }

        pub fn Eapol_build_msg2<'a>(
            snonce: &[u8; 32],
            replay: u64,
        ) -> EapolKeyFrame {
            EapolKeyFrame {
                header: EapolHeader {
                    version: 2,
                    packet_type: 3,
                    length: 0,
                },
                descriptor_type: 2,
                key_info: (1 << 3) | (1 << 8),
                key_length: 16,
                replay_counter: replay,
                key_nonce: *snonce,
                key_iv: [0u8; 16],
                key_rsc: [0u8; 8],
                key_id: [0u8; 8],
                key_mic: [0u8; 16],
                key_data_len: 0,
                key_data: Vec::new(),
            }
        }

        pub fn Eapol_build_msg3<'a>(
            anonce: &[u8; 32],
            replay: u64,
            gtk_kde: &'a [u8],
        ) -> EapolKeyFrame {
            EapolKeyFrame {
                header: EapolHeader {
                    version: 2,
                    packet_type: 3,
                    length: 0,
                },
                descriptor_type: 2,
                key_info: (1 << 3) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9),
                key_length: 16,
                replay_counter: replay,
                key_nonce: *anonce,
                key_iv: [0; 16],
                key_rsc: [0; 8],
                key_id: [0; 8],
                key_mic: [0; 16],
                key_data_len: gtk_kde.len() as u16,
                key_data: gtk_kde.to_vec(),
            }
        }

        pub fn Eapol_build_msg4<'a>(
            replay: u64,
        ) -> EapolKeyFrame {
            EapolKeyFrame {
                header: EapolHeader {
                    version: 2,
                    packet_type: 3,
                    length: 0,
                },
                descriptor_type: 2,
                key_info: (1 << 3) | (1 << 8) | (1 << 9), // pairwise | mic | secure
                key_length: 16,
                replay_counter: replay,
                key_nonce: [0; 32],
                key_iv: [0; 16],
                key_rsc: [0; 8],
                key_id: [0; 8],
                key_mic: [0; 16],
                key_data_len: 0,
                key_data: Vec::new(),
            }
        }

        pub fn Eapol_data_msg1<'a>(
            dst: [u8; 6],
            src: [u8; 6],
            bssid: [u8; 6],
            seq: u16,
            to_ds: bool,
            from_ds: bool,
            anonce:&[u8; 32],
            replay: u64,
        ) -> DataSubType {
            let mut payload: Vec<u8> = Vec::new();
            Eapol_build_msg1(
                    anonce,
                    replay,
                ).serialize(&mut payload);

            forming::data::data(
                dst,
                src,
                bssid,
                seq,
                to_ds,
                from_ds,
                &payload,
            )
        }

        pub fn Eapol_data_msg2<'a>(
            dst: [u8; 6],
            src: [u8; 6],
            bssid: [u8; 6],
            seq: u16,
            to_ds: bool,
            from_ds: bool,
            snonce: &[u8; 32],
            replay: u64,
        ) -> DataSubType {
            let mut payload = Vec::new();
            Eapol_build_msg2(snonce, replay).serialize(&mut payload);

            forming::data::data(
                dst,
                src,
                bssid,
                seq,
                to_ds,
                from_ds,
                &payload,
            )
        }

        pub fn Eapol_data_msg3<'a>(
            dst: [u8; 6],
            src: [u8; 6],
            bssid: [u8; 6],
            seq: u16,
            to_ds: bool,
            from_ds: bool,
            anonce: &[u8; 32],
            replay: u64,
            gtk_kde: &[u8],
        ) -> DataSubType {
            let mut payload = Vec::new();
            Eapol_build_msg3(anonce, replay, gtk_kde).serialize(&mut payload);

            forming::data::data(
                dst,
                src,
                bssid,
                seq,
                to_ds,
                from_ds,
                &payload,
            )
        }

        pub fn Eapol_data_msg4<'a>(
            dst: [u8; 6],
            src: [u8; 6],
            bssid: [u8; 6],
            seq: u16,
            to_ds: bool,
            from_ds: bool,
            replay: u64,
        ) -> DataSubType {
            let mut payload = Vec::new();
            Eapol_build_msg4(replay).serialize(&mut payload);

            forming::data::data(
                dst,
                src,
                bssid,
                seq,
                to_ds,
                from_ds,
                &payload,
            )
        }
    }
}