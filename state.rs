use std::time::Instant;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use crate::data::*;
use crate::management::*;
use crate::control::*;
use crate::common::*;
use crate::ip::*;
use crate::forming;
use log::warn;
use std::time::Duration;
use getrandom;
use crate::crypto::*;

pub enum InterfaceState {
    Idle,
    Scanning,
    Authenticating,
    Authenticated,
    Associated,
    Deauthenticating,
    Roaming,
    LinkLost,
    Associating,
    FourWayHandshake,
    WPAKeyHandshake,
    WaitBeacon,
    Connected,
    Disconnected,
}

#[derive(PartialEq, Eq)]
pub enum StationState {
    NotAuthenticated,
    Authenticated,
    Associated,
    Authorized,
}

pub enum InterfaceMode {
    Station,
    AccessPoint,
    Monitor,
}

enum RsnState {
    None,
    PtkStart {
        pmk: [u8; 32],
        replay_counter: u64,
    },
    PtkNegotiating {
        pmk: [u8; 32],
        anonce: [u8; 32],
        snonce: [u8; 32],
        replay_counter: u64,
    },
    PtkInstalled {
        ptk: [u8; 64],
        replay_counter: u64,
    },
    GtkInstalled {
        ptk: [u8; 64],
        gtk: Vec<u8>,
        replay_counter: u64,
    },
}

pub struct BssEntry {
    bssid: [u8; 6],
    ssid: Option<Vec<u8>>,
    channel: u8,
    rssi: i8,
    beacon_interval: u16,
    last_seen: Instant,
    ie_storage: Vec<u8>,
}

struct AssocInfo {
    aid: u16, //association id
    rsn: RsnState,
}

pub struct ConnectionInfo {
    bssid: [u8; 6],
    state: InterfaceState,
    assoc_info: Option<AssocInfo>,
    last_beacon: Instant,
}

pub struct StationEntry {
    addr: [u8; 6],
    state: StationState,
    aid: u16,
    last_activity: Instant,
    rsn: Option<RsnState>,
}

pub struct Interface<'a> {
    pub mode: InterfaceMode,
    pub state: InterfaceState,
    pub mac_addr: [u8; 6],
    pub conn: Option<ConnectionInfo>,
    pub ap_capability_info: Option<u16>,
    pub bss_table: Vec<BssEntry>,
    // ap_ies: Option<Vec<Ie<'a>>>,
    pub ap_ie_storage: Option<Vec<u8>>,
    pub current_bss: Option<[u8; 6]>,
    pub stations: HashMap<[u8; 6], StationEntry>,
    pub channel: u8,
    pub last_rx: Instant,
    pub auth_timeout: Option<Instant>,
    pub assoc_timeout: Option<Instant>,
    pub eapol_timeout: Option<Instant>,
    pub beacon_loss_deadline: Option<Instant>,

    pub tx: Box<dyn Fn(&[u8]) + 'a>,
}

impl<'a> Interface<'a> {
    fn is_ap(&self) -> bool {
        matches!(self.mode, InterfaceMode::AccessPoint)
    }

    pub fn handle_frame(&mut self, phy: &PHY, now: Instant) {
        let Some(frame) = phy.parse() else { return; }; //parse or drop packet

        match frame {
            FrameType::Management(mgmt) => { self.handle_mgmt(mgmt, now); }
            FrameType::Control(ctrl) => { self.handle_ctrl(ctrl, now); }
            FrameType::Data(data) => { self.handle_data(data, now); }
        }
    }
    fn handle_mgmt(&mut self, mgmt: MgmtSubType, now: Instant) {
        match mgmt {
            MgmtSubType::AssocRequest(f) => { self.process_assoc_request(f, now) }
            MgmtSubType::AssocResponse(f) => { self.process_assoc_response(f, now) }
            MgmtSubType::ProbeRequest(f) => { self.process_probe_request(f, now) }
            MgmtSubType::ProbeResponse(f) => { self.process_probe_response(f, now) }
            MgmtSubType::Beacon(f) => { self.process_beacon(f, now) }
            MgmtSubType::Authentication(f) => { self.process_authentication(f, now) }
        }
    }
    fn handle_ctrl(&mut self, ctrl: CtrlSubType, now: Instant) {
        match ctrl {
            CtrlSubType::Ack(f) => { self.process_ack(f, now) }
        }
    }
    fn handle_data(&mut self, data: DataSubType, now: Instant) {
        match data {
            DataSubType::Data(f) => { self.process_data(f, now) }
        }
    }
    // ----------------------------------------------------------------------------------------------------
    fn process_assoc_request(&mut self, assoc_request: AssocRequestFrame, now: Instant) { //AP side logic responding to request
        if !self.is_ap() {return;} //Drop association request if not access point
        let sta_addr = assoc_request.header.addr2;
        let ap_addr = assoc_request.header.addr1;
        let bssid = assoc_request.header.addr3;
        if ap_addr != self.mac_addr {return;} //Drop association request not meant for us
        if let Some(current) = self.current_bss {if current != bssid {return;}} //Mismatch between bssid and ap bssid
        let aid = (self.stations.len() as u16) + 1;
        
        let entry = match self.stations.entry(sta_addr) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(v) => {
                v.insert(StationEntry {
                    addr: sta_addr,
                    state: StationState::NotAuthenticated,
                    aid,
                    last_activity: now,
                    rsn: None,
                })
            }
        };
        entry.last_activity = now;

        if entry.state != StationState::Authenticated {
            let failure_resp = forming::forming::management::association_response(
                sta_addr,
                self.mac_addr,
                bssid,
                0, //seq (unimplemented)
                0, //capability_info ignored on failure
                1, //status code generic failure until I reference the status codes
                0, //aid 0 on failure
                &Vec::new(), //no ies on failure
            );
            let mut buf = Vec::new();
            failure_resp.serialize(&mut buf);
            let _ = (self.tx)(&buf);

            return;
        } //Strict AP: Must be authenticated before associating

        let success_resp = forming::forming::management::association_response(
            sta_addr,
            self.mac_addr,
            bssid,
            0, //seq (unimplemented)
            assoc_request.capability_info,
            0, //status code success
            entry.aid,
            &self.ap_ie_storage.as_ref().unwrap(),
        );

        entry.state = StationState::Associated;

        let mut buf = Vec::new();
        success_resp.serialize(&mut buf);
        let _ = (self.tx)(&buf);

        let ies = parse_ies(assoc_request.ie_storage.as_slice());
        let has_rsn = ies.iter().any(|ie| ie.id == 48);
        // entry.rsn = if has_rsn { Some(RsnState::None) } else { None };

        if has_rsn {
            // TODO real pmk
            let pmk = [0u8; 32];
            let mut anonce = [0u8; 32];
            getrandom::fill(&mut anonce).unwrap();

            let replay = 1u64;

            entry.rsn = Some(RsnState::PtkNegotiating {
                pmk,
                anonce,
                snonce: [0u8; 32],
                replay_counter: replay,
            });

            let msg1 = forming::forming::Eapol::Eapol_data_msg1(
                sta_addr,
                self.mac_addr,
                bssid,
                0, // unimplemented
                false,
                false,
                &anonce,
                replay,
            );

            let mut buf = Vec::new();
            msg1.serialize(&mut buf);
            let _ = (self.tx)(&buf);

            self.state = InterfaceState::FourWayHandshake;
            self.eapol_timeout = Some(now + Duration::from_secs(1));
        }

        entry.last_activity = now;

        
    }
    // ----------------------------------------------------------------------------------------------------
    fn process_assoc_response(&mut self, assoc_response: AssocResponseFrame, now: Instant) { //STA side logic responding to AP response to association request
        if self.is_ap() {return;} //Drop Association Response if AP
        let dst = assoc_response.header.addr1;
        let src = assoc_response.header.addr2;
        let bssid = assoc_response.header.addr3;
        if dst != self.mac_addr {return;} //Drop frame not meant for us
        let Some(conn) = self.conn.as_mut() else {return;}; //Unexpected Response, frame drop
        if conn.bssid != bssid {return;}
        conn.last_beacon = now;

        if assoc_response.status_code != 0 { //Association failed
            conn.state = InterfaceState::Disconnected;
            conn.assoc_info = None;
            self.assoc_timeout = None;

            return;
        }

        conn.assoc_info = Some(AssocInfo {
            aid: assoc_response.aid,
            rsn: RsnState::None,
        });

        conn.state = InterfaceState::Associated;
        self.assoc_timeout = None;

        let ies = parse_ies(assoc_response.ie_storage.as_slice());
        let has_rsn = ies.iter().any(|ie| ie.id == 48);

        if has_rsn {
            // TODO real pmk
            let pmk = [0u8; 32];
            let mut snonce = [0u8; 32];
            getrandom::fill(&mut snonce).unwrap();

            let replay = 0u64;

            conn.assoc_info.as_mut().unwrap().rsn = RsnState::PtkStart {
                pmk,
                replay_counter: replay,
            };

            conn.state = InterfaceState::FourWayHandshake;
            self.eapol_timeout = Some(now + Duration::from_secs(1))
        } else {
            conn.state = InterfaceState::Connected;
        }
    }
    // ----------------------------------------------------------------------------------------------------
    fn process_probe_request(&mut self, probe_request: ProbeRequestFrame, now: Instant) {
        if !self.is_ap() { return; }
        let sta_addr = probe_request.header.addr2;
        let req_ies = parse_ies(&probe_request.ie_storage);
        let ssid_ie = req_ies.iter().find(|ie| ie.id == 0);
        let ap_ie_storage = match &self.ap_ie_storage {
            Some(bytes) => bytes,
            None => return,
        };
        let ap_ies = parse_ies(ap_ie_storage);
        let matches_ssid = match ssid_ie {
            None => true,
            Some(req) => {
                let our_ssid = ap_ies.iter().find(|ie| ie.id == 0).map(|ie| ie.value);
                let req_ssid = Some(req.value);
                our_ssid == req_ssid
            }
        };
        if !matches_ssid { return; }

        let resp = forming::forming::management::probe_response(
            sta_addr,
            self.mac_addr,
            self.current_bss.unwrap_or(self.mac_addr),
            0, // unimplemented
            0u64,
            self.bss_table[0].beacon_interval,
            self.ap_capability_info.unwrap_or(0u16),
            ap_ie_storage,
        );

        let mut buf = Vec::new();
        resp.serialize(&mut buf);
        (self.tx)(&buf);
    }
    // ----------------------------------------------------------------------------------------------------
    fn process_probe_response(&mut self, probe_response: ProbeResponseFrame, now: Instant) {
        if self.is_ap() { return; }
        let bssid = probe_response.header.addr3;
        let mut ie_storage = Vec::new();
        let ies = parse_ies(&probe_response.ie_storage);
        for ie in &ies {
            ie_storage.push(ie.id);
            ie_storage.push(ie.value.len() as u8);
            ie_storage.extend_from_slice(ie.value);
        }

        let idx = self.bss_table.iter().position(|e| e.bssid == bssid);
        // let parsed_ies = parse_ies(&ie_storage);

        match idx {
            Some(i) => {
                let entry = &mut self.bss_table[i];

                entry.last_seen = now;
                entry.beacon_interval = probe_response.beacon_interval;
                entry.ie_storage = ie_storage;
                let parsed_ies = parse_ies(&entry.ie_storage);
                entry.ssid = parsed_ies.iter().find(|ie| ie.id == 0).map(|ie| ie.value.to_vec());
                entry.channel = parsed_ies.iter().find(|ie| ie.id == 3).map(|ie| ie.value[0]).unwrap_or(self.channel);
                entry.rssi = 0;
            }

            None => {
                self.bss_table.push(BssEntry {
                    bssid,
                    ssid: None,
                    channel: self.channel,
                    rssi: 0,
                    beacon_interval: probe_response.beacon_interval,
                    last_seen: now,
                    ie_storage,
                });

                let entry = self.bss_table.last_mut().unwrap();

                let parsed_ies = parse_ies(&entry.ie_storage);
                entry.ssid = parsed_ies.iter().find(|ie| ie.id == 0).map(|ie| ie.value.to_vec());
                entry.channel = parsed_ies.iter().find(|ie| ie.id == 3).map(|ie| ie.value[0]).unwrap_or(self.channel);
            }
        }
    }
    // ----------------------------------------------------------------------------------------------------
    fn process_beacon(&mut self, beacon: BeaconFrame, now: Instant) {
        if self.is_ap() { return; } // ignore other APs
        let bssid = beacon.header.addr3;
        if let Some(conn) = self.conn.as_mut() {
            if conn.bssid == bssid {
                conn.last_beacon = now;
                let interval_tu = beacon.beacon_interval as u64;
                let interval = Duration::from_micros(interval_tu * 1024);
                self.beacon_loss_deadline = Some(now + interval * 10);
            }
        }

        let idx = self.bss_table.iter().position(|e| e.bssid == bssid);

        match idx {
            Some(i) => {
                let entry = &mut self.bss_table[i];

                entry.last_seen = now;
                entry.beacon_interval = beacon.beacon_interval;
                entry.ie_storage = beacon.ie_storage.clone();

                let parsed_ies = parse_ies(&entry.ie_storage);
                entry.ssid = parsed_ies.iter().find(|ie| ie.id == 0).map(|ie| ie.value.to_vec());
                entry.channel = parsed_ies.iter().find(|ie| ie.id == 3).map(|ie| ie.value[0]).unwrap_or(self.channel);
                entry.rssi = 0; // unimplemented
            }

            None => {
                self.bss_table.push(BssEntry {
                    bssid,
                    ssid: None,
                    channel: self.channel,
                    rssi: 0,
                    beacon_interval: beacon.beacon_interval,
                    last_seen: now,
                    ie_storage: beacon.ie_storage.clone(),
                });

                let entry = self.bss_table.last_mut().unwrap();
                let parsed_ies = parse_ies(&entry.ie_storage);
                entry.ssid = parsed_ies.iter().find(|ie| ie.id == 0).map(|ie| ie.value.to_vec());
                entry.channel = parsed_ies.iter().find(|ie| ie.id == 3).map(|ie| ie.value[0]).unwrap_or(self.channel);
            }
        }
    }
    // ----------------------------------------------------------------------------------------------------
    fn process_authentication(&mut self, authentication: AuthenticationFrame, now: Instant) {
        let dst = authentication.header.addr1;
        let src = authentication.header.addr2;
        let bssid = authentication.header.addr3;

        if self.is_ap() {
            if dst != self.mac_addr { return; }
            if let Some(current) = self.current_bss { if current != bssid { return; } }
            let aid = (self.stations.len() as u16) + 1;

            let entry = match self.stations.entry(src) {
                Entry::Occupied(e) => e.into_mut(),
                Entry::Vacant(v) => {
                    v.insert(StationEntry {
                        addr: src,
                        state: StationState::NotAuthenticated,
                        aid,
                        last_activity: now,
                        rsn: None,
                    })
                }
            };
            entry.last_activity = now;

            let mut status_code = 0u16;
            if authentication.auth_algorithm != 0 || authentication.auth_seq != 1 {
                status_code = 1;
            }

            if status_code == 0 {
                entry.state = StationState::Authenticated;
            }

            let resp = forming::forming::management::authentication(
                src,
                self.mac_addr,
                bssid,
                0,
                2,
                status_code,
                &[],
            );

            let mut buf = Vec::new();
            resp.serialize(&mut buf);
            let _ = (self.tx)(&buf);

            return;
        }
        // STA
        if dst != self.mac_addr { return; }
        let Some(conn) = self.conn.as_mut() else { return; };
        if conn.bssid != bssid { return; }

        if authentication.status_code != 0 || authentication.auth_seq != 2 {
            conn.state = InterfaceState::Disconnected;
            self.auth_timeout = None;
            return;
        }

        conn.state = InterfaceState::Authenticated;
        self.auth_timeout = None;
    }
    // ----------------------------------------------------------------------------------------------------
    fn process_ack(&mut self, ack: AckFrame, now: Instant) {
        // Unprocessed for now, probably match to each outstanding tx when seq is implemented
    }
    // ----------------------------------------------------------------------------------------------------
    fn process_data(&mut self, data: DataFrame, now: Instant) {
        self.last_rx = now;

        if self.is_ap() {
            if let Some(src) = match &data.header {
                DataHeader::ThreeAddr { addr2, .. } => Some(*addr2),
                DataHeader::FourAddr { addr2, .. } => Some(*addr2),
            } {
                if let Some(sta) = self.stations.get_mut(&src) {
                    sta.last_activity = now;
                }
            }
        }

        if let Some(l3) = data.l3_parse() {
            match &l3 {
                L3Packet::EapolKey(key) => {
                    self.process_eapol_key(key, &data, now);
                }
                L3Packet::Eapol(_) => {
                    // Non key Eapol, unimplemented
                }

                L3Packet::Ipv4(_)
                | L3Packet::Ipv6(_)
                | L3Packet::Arp(_)
                | L3Packet::Unknown(_, _) => {
                    // Higher level transfer spot, unimplemented
                }
            }
        }
    }
    // ----------------------------------------------------------------------------------------------------
    fn process_eapol_key(
        &mut self,
        key: &EapolKeyFrame,
        data: &DataFrame,
        now: Instant,
    ) {
        if self.is_ap() {
            self.process_ap_eapol_key(key, data, now);
        } else {
            self.process_sta_eapol_key(key, data, now);
        }
    }

    fn process_ap_eapol_key(
        &mut self,
        key: &EapolKeyFrame,
        data: &DataFrame,
        now: Instant,
    ) {
        let (dst, src, bssid, to_ds, from_ds) = match &data.header {
            DataHeader::ThreeAddr { common, addr1, addr2, addr3, .. } => {
                (*addr1, *addr2, *addr3, common.frame_control.to_ds(), common.frame_control.from_ds())
            }
            DataHeader::FourAddr { common, addr1, addr2, addr3, .. } => {
                (*addr1, *addr2, *addr3, common.frame_control.to_ds(), common.frame_control.from_ds())
            }
        };

        if dst != self.mac_addr { return; }
        if let Some(current) = self.current_bss { if current != bssid { return; } }
        let Some(entry) = self.stations.get_mut(&src) else { return; };
        entry.last_activity = now;

        if key.is_msg2() {
            let rsn_state = match &entry.rsn {
                Some(RsnState::PtkNegotiating {pmk, anonce, ..}) => {
                    (pmk.clone(), anonce.clone())
                }
                _ => { return; }
            };

            let (pmk, anonce) = rsn_state;
            let snonce = key.key_nonce;

            let ptk = derive_ptk(pmk, anonce, snonce, self.mac_addr, src);
            if !verify_mic(ptk, key.clone()) { return; }

            entry.rsn = Some(RsnState::PtkInstalled {
                ptk,
                replay_counter: key.replay_counter,
            });

            let gtk_kde: [u8; 0] = [];
            let resp = forming::forming::Eapol::Eapol_data_msg3(
                src,
                self.mac_addr,
                bssid,
                0, // unimplemented
                to_ds, // these probably shouldn't copy
                from_ds,
                &anonce,
                key.replay_counter + 1,
                &gtk_kde,
            );

            let mut buf = Vec::new();
            resp.serialize(&mut buf);
            let _ = (self.tx)(&buf);

            entry.rsn = Some(RsnState::GtkInstalled {
                ptk,
                gtk: Vec::new(),
                replay_counter: key.replay_counter + 1,
            });
        } else if key.is_msg4() {
            let (ptk, _) = match &entry.rsn {
                Some(RsnState::GtkInstalled { ptk, replay_counter, .. }) => {
                    (ptk.clone(), *replay_counter)
                }
                Some(RsnState::PtkInstalled { ptk, replay_counter }) => {
                    (ptk.clone(), *replay_counter)
                }
                _ => {
                    return;
                }
            };

            if !verify_mic(ptk, key.clone()) { return; }

            entry.state = StationState::Authorized;
        }
    }

    fn process_sta_eapol_key(
        &mut self,
        key: &EapolKeyFrame,
        data: &DataFrame,
        now: Instant,
    ) {
        let (dst, src, bssid, to_ds, from_ds) = match &data.header {
            DataHeader::ThreeAddr { common, addr1, addr2, addr3, .. } => {
                (*addr1, *addr2, *addr3, common.frame_control.to_ds(), common.frame_control.from_ds())
            }
            DataHeader::FourAddr { common, addr1, addr2, addr3, .. } => {
                (*addr1, *addr2, *addr3, common.frame_control.to_ds(), common.frame_control.from_ds())
            }
        };
        if dst != self.mac_addr { return; }
        let Some(conn) = self.conn.as_mut() else { return; };
        if conn.bssid != bssid { return; }
        conn.last_beacon = now;
        let Some(assoc) = conn.assoc_info.as_mut() else { return; };

        if key.is_msg1() {
            let (pmk, _) = match &assoc.rsn {
                RsnState::PtkStart { pmk, replay_counter } => (pmk.clone(), *replay_counter ),
                _ => {
                    return;
                }
            };

            let anonce = key.key_nonce;
            let mut snonce = [0u8; 32];
            getrandom::fill(&mut snonce).unwrap();
            let ptk = derive_ptk(pmk, anonce, snonce, bssid, self.mac_addr);

            assoc.rsn = RsnState::PtkInstalled {
                ptk,
                replay_counter: key.replay_counter,
            };

            let resp = forming::forming::Eapol::Eapol_data_msg2(
                src,
                self.mac_addr,
                bssid,
                0, // unimplemented
                to_ds,
                from_ds,
                &snonce,
                key.replay_counter,
            );

            let mut buf = Vec::new();
            resp.serialize(&mut buf);
            let _ = (self.tx)(&buf);

            conn.state = InterfaceState::FourWayHandshake;
            self.eapol_timeout = Some(now + Duration::from_secs(1));
        } else if key.is_msg3() {
            let (ptk, _) = match &assoc.rsn {
                RsnState::PtkInstalled { ptk, replay_counter } => (ptk.clone(), *replay_counter),
                _ => {
                    return;
                }
            };

            if !verify_mic(ptk, key.clone()) { return; }

            let gtk = if key.key_data_len > 0 {
                decrypt_gtk(ptk, key.key_data.as_slice())
            } else {
                Vec::new()
            };

            assoc.rsn = RsnState::GtkInstalled {
                ptk,
                gtk,
                replay_counter: key.replay_counter,
            };

            let resp = forming::forming::Eapol::Eapol_data_msg4(
                src,
                self.mac_addr,
                bssid,
                0, // unimplemented
                to_ds,
                from_ds,
                key.replay_counter + 1,
            );

            let mut buf = Vec::new();
            resp.serialize(&mut buf);
            let _ = (self.tx)(&buf);

            conn.state = InterfaceState::Connected;
            self.eapol_timeout = None;
        }
    }
}