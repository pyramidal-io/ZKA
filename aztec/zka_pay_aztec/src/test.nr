// ZKAPay ownerless surface exercised against the v6 TXE. These tests use
// authenticated Inbox messages and inspect the recipient's real private-event
// store; a fabricated return value from `pay` cannot satisfy the receipt tests.

use crate::ZKAPay;
use aztec::{
    event::{event_interface::EventInterface, EventSelector},
    messages::{
        encoding::{decode_message, encode_message},
        encryption::{aes128::AES128, message_encryption::MessageEncryption},
        msg_type::{PRIVATE_EVENT_MSG_TYPE_ID, PRIVATE_NOTE_MSG_TYPE_ID},
    },
    note::{HintedNote, note_getter::view_note},
    protocol::{address::{AztecAddress, EthAddress}, traits::{FromField, ToField}},
    test::helpers::{test_environment::TestEnvironment, txe_oracles::get_last_tx_effects},
};
use zka_aztec_lib::pay_receipt::{
    ZKA_PAY_RECEIPT_V1_DOMAIN, ZKA_PAY_RECEIPT_V1_VERSION, ZKAPayReceiptV1,
};
use zka_aztec_lib::ZKANote;

global ASSET_X: Field = 0x1111;
global ASSET_Y: Field = 0x2222;
global TEST_PORTAL: EthAddress = EthAddress::from_field(0xbeefbeef);
global CLAIM_SECRET: Field = 0x123456;
global CONTEXT: Field = 0x987654;

#[test]
fn deposit_content_matches_l1_portal_golden() {
    let l1_content: Field = 0x0087ee5a621afb4fde01701656cff070640af03e3b4bc551975c6e3168dcb6bb;
    assert(
        crate::deposit::deposit_content_hash(0xbeef, ASSET_X, 1000) == l1_content,
        "deposit claim content must match L1 portal",
    );
}

#[test(should_fail)]
fn aggregate_note_values_cannot_overflow_u128() {
    let max_u128: u128 = 0xffffffffffffffffffffffffffffffff;
    let _ = crate::conservation::conserved_change([max_u128, 1], 2, 1);
}

#[test]
fn largest_field_has_canonical_be_encoding() {
    let max_field: Field = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000;
    let expected: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00,
        0x00, 0x00,
    ];
    let actual = crate::withdrawal::canonical_be_bytes_32(max_field);
    for i in 0..32 {
        assert(actual[i] == expected[i], "p-1 must have one canonical byte encoding");
    }
}

#[test]
fn withdrawal_content_matches_l1_portal_encoding() {
    // sha256(selector("withdraw(address,uint256)") || abi.encode(0xabcd, 25)),
    // with the final digest byte discarded by Aztec's sha256_to_field.
    let l1_content: Field = 0xaac1c1382a49787ecbedd085692b151a3f9af62ad7cc7e87df65acdeaadaa2;
    assert(
        crate::withdrawal::withdraw_content_hash(0xabcd, 25) == l1_content,
        "withdrawal content must match the L1 portal's exact ABI preimage",
    );
}

// Aztec.nr v6 exposes this TXE oracle as pub(crate), so contract-package tests
// declare its public oracle wire signature locally. The implementation is the
// actual TXE event store, keyed by selector, contract, and recipient scope.
#[oracle(aztec_txe_getPrivateEvents)]
unconstrained fn get_private_events(
    selector: EventSelector,
    contract_address: AztecAddress,
    scope: AztecAddress,
) -> BoundedVec<BoundedVec<Field, 10>, 5> {}

unconstrained fn setup() -> (TestEnvironment, AztecAddress, AztecAddress, AztecAddress, AztecAddress) {
    let mut env = TestEnvironment::new();
    let sender = env.create_light_account();
    let recipient = env.create_light_account();
    let bystander = env.create_light_account();
    let initializer = ZKAPay::interface().constructor(TEST_PORTAL, ASSET_X);
    let addr = env.deploy("ZKAPay").with_public_initializer(sender, initializer);
    (env, addr, sender, recipient, bystander)
}

unconstrained fn seed_deposit(
    env: TestEnvironment,
    addr: AztecAddress,
    beneficiary: AztecAddress,
    asset: Field,
    amount: u128,
    secret: Field,
    portal: EthAddress,
) -> Field {
    let content = crate::deposit::deposit_content_hash(beneficiary.to_field(), asset, amount);
    env.send_l1_to_l2_message(content, secret, portal, addr)
}

unconstrained fn claim(
    env: TestEnvironment,
    addr: AztecAddress,
    caller: AztecAddress,
    beneficiary: AztecAddress,
    amount: u128,
) -> Field {
    let leaf = seed_deposit(
        env,
        addr,
        beneficiary,
        ASSET_X,
        amount,
        CLAIM_SECRET,
        TEST_PORTAL,
    );
    env.call_private(caller, ZKAPay::at(addr).claim_private(beneficiary, amount, CLAIM_SECRET, leaf));
    leaf
}

unconstrained fn balance(
    env: TestEnvironment,
    addr: AztecAddress,
    owner: AztecAddress,
    asset: Field,
) -> Field {
    env.execute_utility(ZKAPay::at(addr).get_balance(owner, asset))
}

unconstrained fn receipts(
    addr: AztecAddress,
    recipient: AztecAddress,
) -> BoundedVec<BoundedVec<Field, 10>, 5> {
    get_private_events(ZKAPayReceiptV1::get_event_type_id(), addr, recipient)
}

// Select by recipient decryption and event selector over the actual TXE
// private logs. The holder must retain the matched canonical array index.
unconstrained fn last_pay_receipt_ciphertext(
    env: TestEnvironment,
    addr: AztecAddress,
    recipient: AztecAddress,
) -> [Field; 15] {
    let effects = get_last_tx_effects();
    env.utility_context_at(addr, |_| {
        let mut found = false;
        let mut selected: [Field; 15] = [0; 15];
        for log_index in 0..effects.private_logs.len() {
            let log = effects.private_logs.get(log_index);
            if log.len() == 16 {
                let mut candidate: [Field; 15] = [0; 15];
                for i in 0..15 {
                    candidate[i] = log.get(i + 1);
                }
                let decrypted =
                    AES128::decrypt(BoundedVec::from_array(candidate), recipient, addr);
                if decrypted.is_some() {
                    let message = decode_message(decrypted.unwrap());
                    if message.is_some() {
                        let (kind, selector, _content) = message.unwrap();
                        if kind == PRIVATE_EVENT_MSG_TYPE_ID {
                            if selector == ZKAPayReceiptV1::get_event_type_id().to_field() as u64 {
                                assert(!found, "pay must have one receipt ciphertext");
                                found = true;
                                selected = candidate;
                            }
                        }
                    }
                }
            }
        }
        assert(found, "pay must have one recipient receipt ciphertext");
        selected
    })
}

// Synthetic ciphertexts exercise the utility's closed decoder. Delivery
// evidence comes from the real-pay private-log tests above.
unconstrained fn synthetic_ciphertext(
    env: TestEnvironment,
    addr: AztecAddress,
    recipient: AztecAddress,
    message_type: u64,
    content: [Field; 6],
) -> [Field; 15] {
    env.utility_context_at(addr, |_| {
        let message = encode_message(
            message_type,
            ZKAPayReceiptV1::get_event_type_id().to_field() as u64,
            content,
        );
        AES128::encrypt(message, recipient, addr)
    })
}

unconstrained fn synthetic_receipt_content(instance: AztecAddress) -> [Field; 6] {
    [
        0x1234,
        ZKA_PAY_RECEIPT_V1_DOMAIN,
        ZKA_PAY_RECEIPT_V1_VERSION,
        CONTEXT,
        0x5678,
        instance.to_field(),
    ]
}

#[test]
unconstrained fn recipient_decodes_exact_receipt_from_actual_pay_private_log() {
    let (env, addr, sender, recipient, _bystander) = setup();
    let _ = claim(env, addr, sender, sender, 100);
    env.call_private(sender, ZKAPay::at(addr).pay(recipient, ASSET_X, 37, CONTEXT));
    let ciphertext = last_pay_receipt_ciphertext(env, addr, recipient);
    let decoded = env.execute_utility(ZKAPay::at(addr).decode_receipt_log(recipient, ciphertext));
    let delivered = receipts(addr, recipient);
    assert(delivered.len() == 1, "recipient must have one validated event");
    let body = delivered.get(0);
    assert(decoded[1] == body.get(0), "decoded domain must match validated event");
    assert(decoded[2] == body.get(1), "decoded version must match validated event");
    assert(decoded[3] == body.get(2), "decoded context must match validated event");
    assert(decoded[4] == body.get(3), "decoded note hash must match validated event");
    assert(decoded[5] == body.get(4), "decoded instance must match validated event");
}

#[test(should_fail_with = "Receipt ciphertext cannot be decrypted")]
unconstrained fn bystander_cannot_decode_recipient_receipt_log() {
    let (env, addr, sender, recipient, bystander) = setup();
    let _ = claim(env, addr, sender, sender, 100);
    env.call_private(sender, ZKAPay::at(addr).pay(recipient, ASSET_X, 37, CONTEXT));
    let ciphertext = last_pay_receipt_ciphertext(env, addr, recipient);
    let _ = env.execute_utility(ZKAPay::at(addr).decode_receipt_log(bystander, ciphertext));
}

#[test(should_fail_with = "Receipt message type is invalid")]
unconstrained fn synthetic_non_event_ciphertext_is_rejected() {
    let (env, addr, _sender, recipient, _bystander) = setup();
    let ciphertext = synthetic_ciphertext(
        env,
        addr,
        recipient,
        PRIVATE_NOTE_MSG_TYPE_ID,
        synthetic_receipt_content(addr),
    );
    let _ = env.execute_utility(ZKAPay::at(addr).decode_receipt_log(recipient, ciphertext));
}

#[test(should_fail_with = "Receipt version is invalid")]
unconstrained fn synthetic_wrong_receipt_version_is_rejected() {
    let (env, addr, _sender, recipient, _bystander) = setup();
    let mut content = synthetic_receipt_content(addr);
    content[2] = 2;
    let ciphertext = synthetic_ciphertext(env, addr, recipient, PRIVATE_EVENT_MSG_TYPE_ID, content);
    let _ = env.execute_utility(ZKAPay::at(addr).decode_receipt_log(recipient, ciphertext));
}

#[test(should_fail_with = "Receipt contract instance is invalid")]
unconstrained fn synthetic_wrong_receipt_instance_is_rejected() {
    let (env, addr, _sender, recipient, bystander) = setup();
    let content = synthetic_receipt_content(bystander);
    let ciphertext = synthetic_ciphertext(env, addr, recipient, PRIVATE_EVENT_MSG_TYPE_ID, content);
    let _ = env.execute_utility(ZKAPay::at(addr).decode_receipt_log(recipient, ciphertext));
}

#[test(should_fail_with = "Receipt ciphertext cannot be decrypted")]
unconstrained fn malformed_ciphertext_is_rejected() {
    let (env, addr, _sender, recipient, _bystander) = setup();
    let _ = env.execute_utility(ZKAPay::at(addr).decode_receipt_log(recipient, [0; 15]));
}

#[test(should_fail_with = "Receipt content length is invalid")]
unconstrained fn synthetic_short_receipt_is_rejected() {
    let (env, addr, _sender, recipient, _bystander) = setup();
    let ciphertext = env.utility_context_at(addr, |_| {
        let message = encode_message(
            PRIVATE_EVENT_MSG_TYPE_ID,
            ZKAPayReceiptV1::get_event_type_id().to_field() as u64,
            [0x1234, ZKA_PAY_RECEIPT_V1_DOMAIN, ZKA_PAY_RECEIPT_V1_VERSION, CONTEXT, 0x5678],
        );
        AES128::encrypt(message, recipient, addr)
    });
    let _ = env.execute_utility(ZKAPay::at(addr).decode_receipt_log(recipient, ciphertext));
}

#[test(should_fail_with = "Receipt event selector is invalid")]
unconstrained fn synthetic_wrong_selector_is_rejected() {
    let (env, addr, _sender, recipient, _bystander) = setup();
    let ciphertext = env.utility_context_at(addr, |_| {
        let message = encode_message(
            PRIVATE_EVENT_MSG_TYPE_ID,
            (ZKAPayReceiptV1::get_event_type_id().to_field() as u64) + 1,
            synthetic_receipt_content(addr),
        );
        AES128::encrypt(message, recipient, addr)
    });
    let _ = env.execute_utility(ZKAPay::at(addr).decode_receipt_log(recipient, ciphertext));
}

#[test(should_fail_with = "Receipt domain is invalid")]
unconstrained fn synthetic_wrong_domain_is_rejected() {
    let (env, addr, _sender, recipient, _bystander) = setup();
    let mut content = synthetic_receipt_content(addr);
    content[1] = 0;
    let ciphertext = synthetic_ciphertext(env, addr, recipient, PRIVATE_EVENT_MSG_TYPE_ID, content);
    let _ = env.execute_utility(ZKAPay::at(addr).decode_receipt_log(recipient, ciphertext));
}

#[test(should_fail_with = "Receipt context must be non-zero")]
unconstrained fn synthetic_zero_context_is_rejected() {
    let (env, addr, _sender, recipient, _bystander) = setup();
    let mut content = synthetic_receipt_content(addr);
    content[3] = 0;
    let ciphertext = synthetic_ciphertext(env, addr, recipient, PRIVATE_EVENT_MSG_TYPE_ID, content);
    let _ = env.execute_utility(ZKAPay::at(addr).decode_receipt_log(recipient, ciphertext));
}

#[test]
unconstrained fn pay_delivers_exact_private_receipt_only_to_note_recipient() {
    let (env, addr, sender, recipient, bystander) = setup();
    let _ = claim(env, addr, sender, sender, 100);

    env.call_private(sender, ZKAPay::at(addr).pay(recipient, ASSET_X, 37, CONTEXT));

    assert(balance(env, addr, sender, ASSET_X) == 63, "pay must return sender change");
    assert(balance(env, addr, recipient, ASSET_X) == 37, "pay must create recipient note");
    let delivered = receipts(addr, recipient);
    assert(delivered.len() == 1, "pay must deliver exactly one recipient receipt");
    let body = delivered.get(0);
    assert(body.len() == 5, "receipt must have exactly five application fields");
    assert(body.get(0) == ZKA_PAY_RECEIPT_V1_DOMAIN, "receipt domain");
    assert(body.get(1) == ZKA_PAY_RECEIPT_V1_VERSION, "receipt version");
    assert(body.get(2) == CONTEXT, "receipt must carry exact interaction context");
    // Recover the actual TXE-discovered note opening from the payee's scope.
    // The fourth field must equal its canonical unsiloed ZKANote hash exactly;
    // zero is not rejected because it is a valid hash output by definition.
    let output_note_hash = env.utility_context_at(addr, |_| {
        let output: HintedNote<ZKANote> =
            view_note(Option::some(recipient), ZKAPay::storage_layout().notes.slot);
        assert(output.owner == recipient, "discovered note belongs to payee");
        assert(output.note.asset_commitment == ASSET_X, "discovered note asset");
        assert(output.note.value == 37, "discovered note value");
        output.note.zka_note_hash(output.owner, output.randomness)
    });
    assert(body.get(3) == output_note_hash, "receipt must bind exact discovered output note");
    assert(body.get(4) == addr.to_field(), "receipt must bind contract instance");
    assert(receipts(addr, sender).len() == 0, "sender must not receive recipient receipt");
    assert(receipts(addr, bystander).len() == 0, "bystander must not decrypt receipt");
}

#[test]
unconstrained fn same_context_can_bind_two_distinct_payment_output_notes() {
    let (env, addr, sender, recipient, _bystander) = setup();
    let _ = claim(env, addr, sender, sender, 100);

    env.call_private(sender, ZKAPay::at(addr).pay(recipient, ASSET_X, 10, CONTEXT));
    env.call_private(sender, ZKAPay::at(addr).pay(recipient, ASSET_X, 20, CONTEXT));

    let delivered = receipts(addr, recipient);
    assert(delivered.len() == 2, "context reuse must preserve both receipts");
    let first = delivered.get(0);
    let second = delivered.get(1);
    assert(first.get(2) == CONTEXT, "first context must be exact");
    assert(second.get(2) == CONTEXT, "second context must be exact");
    assert(first.get(3) != second.get(3), "different output notes need distinct bindings");
    assert(balance(env, addr, sender, ASSET_X) == 70, "both payments conserve change");
    assert(balance(env, addr, recipient, ASSET_X) == 30, "recipient owns both outputs");
}

#[test]
unconstrained fn plain_transfer_creates_note_without_payment_receipt() {
    let (env, addr, sender, recipient, _bystander) = setup();
    let _ = claim(env, addr, sender, sender, 90);

    env.call_private(sender, ZKAPay::at(addr).transfer(recipient, ASSET_X, 35));

    assert(balance(env, addr, sender, ASSET_X) == 55, "plain transfer returns change");
    assert(balance(env, addr, recipient, ASSET_X) == 35, "plain transfer credits recipient");
    assert(receipts(addr, recipient).len() == 0, "plain transfer has no payment context");
}

#[test]
unconstrained fn payment_recipient_can_plain_transfer_without_context() {
    let (env, addr, sender, recipient, bystander) = setup();
    let _ = claim(env, addr, sender, sender, 90);
    env.call_private(sender, ZKAPay::at(addr).pay(recipient, ASSET_X, 50, CONTEXT));

    env.call_private(recipient, ZKAPay::at(addr).transfer(bystander, ASSET_X, 20));

    assert(balance(env, addr, recipient, ASSET_X) == 30, "recipient retains change");
    assert(balance(env, addr, bystander, ASSET_X) == 20, "plain transfer remains available");
    assert(receipts(addr, bystander).len() == 0, "plain transfer adds no receipt");
}

#[test]
unconstrained fn withdraw_after_payment_requires_no_context_or_permission() {
    let (env, addr, sender, recipient, _bystander) = setup();
    let _ = claim(env, addr, sender, sender, 100);
    env.call_private(sender, ZKAPay::at(addr).pay(recipient, ASSET_X, 60, CONTEXT));

    env.call_private(recipient, ZKAPay::at(addr).withdraw(25, ASSET_X, 0xabcd));

    assert(balance(env, addr, recipient, ASSET_X) == 35, "withdraw returns change without a gate");
    assert(balance(env, addr, sender, ASSET_X) == 40, "withdraw never debits sender");
}

#[test]
unconstrained fn pay_conserves_all_selected_notes() {
    let (env, addr, sender, recipient, _bystander) = setup();
    let _ = claim(env, addr, sender, sender, 100);
    let _ = claim(env, addr, sender, sender, 50);
    let _ = claim(env, addr, sender, sender, 30);

    env.call_private(sender, ZKAPay::at(addr).pay(recipient, ASSET_X, 120, CONTEXT));

    assert(balance(env, addr, sender, ASSET_X) == 60, "all consumed value returns as change");
    assert(balance(env, addr, recipient, ASSET_X) == 120, "recipient receives exact value");
}

#[test]
unconstrained fn authenticated_claim_binds_beneficiary_and_mints_no_caller_note() {
    let (env, addr, caller, beneficiary, _bystander) = setup();
    let _ = claim(env, addr, caller, beneficiary, 45);

    assert(balance(env, addr, beneficiary, ASSET_X) == 45, "beneficiary owns claimed note");
    assert(balance(env, addr, caller, ASSET_X) == 0, "claim submitter captures nothing");
}

#[test(should_fail_with = "No non-nullified L1 to L2 message found for message hash")]
unconstrained fn claimed_inbox_leaf_cannot_be_replayed() {
    let (env, addr, sender, recipient, _bystander) = setup();
    let leaf = claim(env, addr, sender, recipient, 45);
    env.call_private(sender, ZKAPay::at(addr).claim_private(recipient, 45, CLAIM_SECRET, leaf));
}

#[test(should_fail_with = "No L1 to L2 message found for message hash")]
unconstrained fn claim_rejects_wrong_secret() {
    let (env, addr, sender, recipient, _bystander) = setup();
    let leaf = seed_deposit(env, addr, recipient, ASSET_X, 45, CLAIM_SECRET, TEST_PORTAL);
    env.call_private(sender, ZKAPay::at(addr).claim_private(recipient, 45, CLAIM_SECRET + 1, leaf));
}

#[test(should_fail_with = "No L1 to L2 message found for message hash")]
unconstrained fn claim_rejects_redirected_beneficiary() {
    let (env, addr, sender, recipient, _bystander) = setup();
    let leaf = seed_deposit(env, addr, recipient, ASSET_X, 45, CLAIM_SECRET, TEST_PORTAL);
    env.call_private(sender, ZKAPay::at(addr).claim_private(sender, 45, CLAIM_SECRET, leaf));
}

#[test(should_fail_with = "No L1 to L2 message found for message hash")]
unconstrained fn claim_rejects_wrong_amount() {
    let (env, addr, sender, recipient, _bystander) = setup();
    let leaf = seed_deposit(env, addr, recipient, ASSET_X, 45, CLAIM_SECRET, TEST_PORTAL);
    env.call_private(sender, ZKAPay::at(addr).claim_private(recipient, 46, CLAIM_SECRET, leaf));
}

#[test(should_fail_with = "No L1 to L2 message found for message hash")]
unconstrained fn claim_rejects_other_asset_message() {
    let (env, addr, sender, recipient, _bystander) = setup();
    let leaf = seed_deposit(env, addr, recipient, ASSET_Y, 45, CLAIM_SECRET, TEST_PORTAL);
    env.call_private(sender, ZKAPay::at(addr).claim_private(recipient, 45, CLAIM_SECRET, leaf));
}

#[test(should_fail_with = "No L1 to L2 message found for message hash")]
unconstrained fn claim_rejects_other_portal_message() {
    let (env, addr, sender, recipient, _bystander) = setup();
    let other_portal = EthAddress::from_field(0xdeadbeef);
    let leaf = seed_deposit(
        env,
        addr,
        recipient,
        ASSET_X,
        45,
        CLAIM_SECRET,
        other_portal,
    );
    env.call_private(sender, ZKAPay::at(addr).claim_private(recipient, 45, CLAIM_SECRET, leaf));
}

#[test(should_fail_with = "ZKA pay receipt context must be nonzero")]
unconstrained fn pay_rejects_zero_interaction_context() {
    let (env, addr, sender, recipient, _bystander) = setup();
    let _ = claim(env, addr, sender, sender, 50);
    env.call_private(sender, ZKAPay::at(addr).pay(recipient, ASSET_X, 10, 0));
}

#[test(should_fail_with = "Transfer value must be non-zero")]
unconstrained fn pay_rejects_zero_value() {
    let (env, addr, sender, recipient, _bystander) = setup();
    let _ = claim(env, addr, sender, sender, 50);
    env.call_private(sender, ZKAPay::at(addr).pay(recipient, ASSET_X, 0, CONTEXT));
}

#[test(should_fail_with = "Asset must match immutable commitment")]
unconstrained fn pay_cannot_spend_an_asset_without_notes() {
    let (env, addr, sender, recipient, _bystander) = setup();
    let _ = claim(env, addr, sender, sender, 50);
    env.call_private(sender, ZKAPay::at(addr).pay(recipient, ASSET_Y, 10, CONTEXT));
}

#[test(should_fail_with = "insufficient balance")]
unconstrained fn pay_rejects_value_above_balance() {
    let (env, addr, sender, recipient, _bystander) = setup();
    let _ = claim(env, addr, sender, sender, 50);
    env.call_private(sender, ZKAPay::at(addr).pay(recipient, ASSET_X, 51, CONTEXT));
}

#[test(should_fail_with = "value exceeds u128 range")]
unconstrained fn pay_rejects_value_above_u128_before_cast() {
    let (env, addr, sender, recipient, _bystander) = setup();
    let _ = claim(env, addr, sender, sender, 50);
    env.call_private(
        sender,
        ZKAPay::at(addr).pay(recipient, ASSET_X, 0x100000000000000000000000000000000, CONTEXT),
    );
}

#[test(should_fail_with = "call to assert_max_bit_size")]
unconstrained fn withdraw_rejects_noncanonical_l1_recipient() {
    let (env, addr, sender, _recipient, _bystander) = setup();
    let _ = claim(env, addr, sender, sender, 50);
    env.call_private(
        sender,
        ZKAPay::at(addr).withdraw(10, ASSET_X, 0x10000000000000000000000000000000000000000),
    );
}

#[test]
unconstrained fn largest_u160_withdrawal_recipient_is_accepted() {
    let (env, addr, sender, _recipient, _bystander) = setup();
    let _ = claim(env, addr, sender, sender, 50);
    env.call_private(
        sender,
        ZKAPay::at(addr).withdraw(10, ASSET_X, 0xffffffffffffffffffffffffffffffffffffffff),
    );
    assert(balance(env, addr, sender, ASSET_X) == 40, "valid L1 recipient must not freeze exit");
}

#[test(should_fail_with = "Function _process_withdrawal can only be called by the same contract")]
unconstrained fn caller_cannot_forge_public_withdrawal_message() {
    let (env, addr, sender, _recipient, _bystander) = setup();
    env.call_public(sender, ZKAPay::at(addr)._process_withdrawal(0xabcd, 25));
}

// No message or spendable note is seeded: the named guard must fail first.
#[test(should_fail_with = "Beneficiary must be a valid Aztec address")]
unconstrained fn claim_private_rejects_invalid_recipient_before_message_lookup() {
    let (env, addr, sender, _, _) = setup();
    env.call_private(
        sender,
        ZKAPay::at(addr).claim_private(AztecAddress::from_field(3), 1, CLAIM_SECRET, 0),
    );
}

#[test(should_fail_with = "Recipient must be a valid Aztec address")]
unconstrained fn transfer_rejects_invalid_recipient_before_spending() {
    let (env, addr, sender, _, _) = setup();
    env.call_private(sender, ZKAPay::at(addr).transfer(AztecAddress::from_field(3), ASSET_X, 1));
}

#[test(should_fail_with = "Recipient must be a valid Aztec address")]
unconstrained fn pay_rejects_invalid_recipient_before_spending() {
    let (env, addr, sender, _, _) = setup();
    env.call_private(sender, ZKAPay::at(addr).pay(AztecAddress::from_field(3), ASSET_X, 1, CONTEXT));
}

// A full pop fills a call frame's nullifier vector, and `pay` adds two delivery
// nullifiers, an event commitment and a change delivery to its own frame. This
// fails with "push out of bounds" if `_spend` is inlined into `pay`.
#[test]
unconstrained fn pay_spends_sixteen_notes_with_change_and_receipt() {
    let (env, addr, sender, recipient, _bystander) = setup();
    for _ in 0..16 {
        let _ = claim(env, addr, sender, sender, 10);
    }

    env.call_private(sender, ZKAPay::at(addr).pay(recipient, ASSET_X, 155, CONTEXT));

    assert(balance(env, addr, sender, ASSET_X) == 5, "pay must return sender change");
    assert(balance(env, addr, recipient, ASSET_X) == 155, "pay must create recipient note");
    assert(receipts(addr, recipient).len() == 1, "pay must deliver exactly one receipt");
}

// `_spend` trusts `from`, so only this contract's entrypoints may reach it.
#[test(should_fail_with = "Function _spend can only be called by the same contract")]
unconstrained fn spend_rejects_direct_call_for_another_owner() {
    let (env, addr, sender, recipient, _bystander) = setup();
    let _ = claim(env, addr, sender, sender, 100);

    env.call_private(recipient, ZKAPay::at(addr)._spend(sender, ASSET_X, 40));
}
