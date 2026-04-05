use crate::ip::EapolKeyFrame;

pub fn derive_ptk(
    pmk: [u8; 32],
    anonce: [u8; 32],
    snonce: [u8; 32],
    aa: [u8; 6],
    spa: [u8; 6],
) -> [u8; 64] {
    [0x11; 64] // placeholder fake pmk
}

pub fn verify_mic(
    ptk: [u8; 64],
    key: EapolKeyFrame
) -> bool {
    true // placeholder fake verification
}

pub fn decrypt_gtk(
    ptk: [u8; 64],
    key_data: &[u8]
) -> Vec<u8> {
    Vec::new() // unimplemente3d
}