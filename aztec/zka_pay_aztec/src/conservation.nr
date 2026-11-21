// Checked value conservation for every multi-note spend.
pub fn conserved_change<let N: u32>(values: [u128; N], count: u32, amount: u128) -> u128 {
    let mut total: u128 = 0;
    for i in 0..N {
        if i < count {
            total += values[i];
        }
    }
    assert(total >= amount, "insufficient balance");
    total - amount
}

// Noir field-to-u128 casts truncate without this round-trip range check.
pub fn assert_fits_u128(v: Field) {
    assert(v == (v as u128) as Field, "value exceeds u128 range");
}
