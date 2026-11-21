use aztec::protocol::hash::sha256_to_field;
use std::field::bn254::decompose;

// Decompose into range-checked limbs to prevent non-canonical 32-byte
// witnesses from changing a withdrawal message's content.
pub fn canonical_be_bytes_32(x: Field) -> [u8; 32] {
    let (lo, hi) = decompose(x);
    let hi_bytes: [u8; 16] = hi.to_be_bytes();
    let lo_bytes: [u8; 16] = lo.to_be_bytes();
    let mut out: [u8; 32] = [0; 32];
    for i in 0..16 {
        out[i] = hi_bytes[i];
        out[i + 16] = lo_bytes[i];
    }
    out
}

pub fn assert_fits_u160(v: Field) {
    zka_lib::assert_fits_u160(v)
}

pub fn withdraw_content_hash(recipient: Field, amount: Field) -> Field {
    let selector: [u8; 4] = [0xf3, 0xfe, 0xf3, 0xa3];
    let recipient_bytes = canonical_be_bytes_32(recipient);
    let amount_bytes = canonical_be_bytes_32(amount);
    let mut hash_bytes: [u8; 68] = [0; 68];
    for i in 0..4 {
        hash_bytes[i] = selector[i];
    }
    for i in 0..32 {
        hash_bytes[i + 4] = recipient_bytes[i];
        hash_bytes[i + 36] = amount_bytes[i];
    }
    sha256_to_field(hash_bytes)
}
