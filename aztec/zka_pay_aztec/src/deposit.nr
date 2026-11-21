use crate::withdrawal::canonical_be_bytes_32;
use aztec::protocol::hash::sha256_to_field;

// Matches the L1 portal's claim_private(bytes32,bytes32,uint256) inbox content.
pub fn deposit_content_hash(beneficiary: Field, asset: Field, amount: u128) -> Field {
    let selector: [u8; 4] = [0x42, 0x67, 0x6e, 0x57];
    let beneficiary_bytes = canonical_be_bytes_32(beneficiary);
    let asset_bytes = canonical_be_bytes_32(asset);
    let amount_bytes = canonical_be_bytes_32(amount as Field);
    let mut hash_bytes: [u8; 100] = [0; 100];
    for i in 0..4 {
        hash_bytes[i] = selector[i];
    }
    for i in 0..32 {
        hash_bytes[i + 4] = beneficiary_bytes[i];
        hash_bytes[i + 36] = asset_bytes[i];
        hash_bytes[i + 68] = amount_bytes[i];
    }
    sha256_to_field(hash_bytes)
}
