// Ownerless Aztec-native ZKA/Pay settlement contract.  No caller, administrator,
// or external registry can alter note validity or the immutable exit portal.
// ZKATransfer remains a distinct legacy contract.
mod conservation;
mod deposit;
mod test;
mod withdrawal;

use aztec::macros::aztec;

#[aztec]
pub contract ZKAPay {
    use crate::conservation::{assert_fits_u128, conserved_change};
    use aztec::{
        event::event_interface::EventInterface,
        macros::{functions::{external, initializer, internal, only_self}, storage::storage},
        messages::{
            delivery::MessageDelivery,
            encoding::{decode_message, MESSAGE_CIPHERTEXT_LEN},
            encryption::{aes128::AES128, message_encryption::MessageEncryption},
            msg_type::PRIVATE_EVENT_MSG_TYPE_ID,
        },
        note::{
            note_getter_options::{NoteGetterOptions, SortOrder},
            note_interface::NoteProperties,
            NoteMessage,
        },
        protocol::{
            address::{AztecAddress, EthAddress},
            constants::MAX_NOTE_HASH_READ_REQUESTS_PER_CALL,
            traits::ToField,
        },
        state_vars::{Owned, PrivateSet, PublicImmutable},
        utils::comparison::Comparator,
    };
    use zka_aztec_lib::{
        pay_receipt::{ZKA_PAY_RECEIPT_V1_DOMAIN, ZKA_PAY_RECEIPT_V1_VERSION, ZKAPayReceiptV1},
        ZKANote,
    };

    // A full pop fills the frame's nullifier vector, so `_spend` must stay its
    // own call frame; see the frame budget note in ZKATransfer.
    global MAX_SPEND_NOTES: u32 = MAX_NOTE_HASH_READ_REQUESTS_PER_CALL;

    #[storage]
    struct Storage<Context> {
        notes: Owned<PrivateSet<ZKANote, Context>, Context>,
        portal: PublicImmutable<EthAddress, Context>,
        asset_commitment: PublicImmutable<Field, Context>,
    }

    #[external("public")]
    #[initializer]
    fn constructor(portal: EthAddress, asset_commitment: Field) {
        assert(!portal.is_zero(), "Portal must be non-zero");
        assert(asset_commitment != 0, "Asset commitment must be non-zero");
        self.storage.portal.initialize(portal);
        self.storage.asset_commitment.initialize(asset_commitment);
    }

    /// A portal message fixes the beneficiary, immutable asset and amount.
    /// Anyone may submit the claim, but only the beneficiary receives the note.
    #[external("private")]
    fn claim_private(
        beneficiary: AztecAddress,
        amount: u128,
        claim_secret: Field,
        message_leaf_index: Field,
    ) {
        assert(!beneficiary.is_zero(), "Beneficiary must be non-zero");
        assert(amount != 0, "Deposit amount must be non-zero");
        assert(beneficiary.is_valid(), "Beneficiary must be a valid Aztec address");
        let asset_commitment = self.storage.asset_commitment.read();
        let content =
            crate::deposit::deposit_content_hash(beneficiary.to_field(), asset_commitment, amount);
        let portal = self.storage.portal.read();
        self.context.consume_l1_to_l2_message(content, [claim_secret], portal, message_leaf_index);
        self
            .storage
            .notes
            .at(beneficiary)
            .insert(ZKANote::new(asset_commitment, amount as Field))
            .deliver(MessageDelivery::onchain_constrained());
    }

    /// Direct owner spend.  The private note is delivered to the payee.
    #[external("private")]
    fn transfer(to: AztecAddress, asset_commitment: Field, value: Field) {
        assert(!to.is_zero(), "Recipient must be non-zero");
        assert(value != 0, "Transfer value must be non-zero");
        assert(to.is_valid(), "Recipient must be a valid Aztec address");
        self.internal._assert_asset(asset_commitment);
        let from = self.msg_sender();
        let change = self.call_self._spend(from, asset_commitment, value);
        self.storage.notes.at(to).insert(ZKANote::new(asset_commitment, value)).deliver(
            MessageDelivery::onchain_constrained(),
        );
        self.internal._return_change(from, asset_commitment, change);
    }

    /// Direct owner spend with one recipient-encrypted ZKA/Pay receipt.
    /// The receipt binds the exact newly created output note opening and this
    /// contract instance.  No context enters public storage or the outbox.
    #[external("private")]
    fn pay(to: AztecAddress, asset_commitment: Field, value: Field, interaction_context: Field) {
        assert(!to.is_zero(), "Recipient must be non-zero");
        assert(value != 0, "Transfer value must be non-zero");
        assert(interaction_context != 0, "ZKA pay receipt context must be nonzero");
        assert(to.is_valid(), "Recipient must be a valid Aztec address");
        self.internal._assert_asset(asset_commitment);
        let from = self.msg_sender();
        let change = self.call_self._spend(from, asset_commitment, value);

        // Extract the same framework-created opening used for the inserted
        // ZKANote hash; do not substitute an independent receipt randomness.
        let output =
            self.storage.notes.at(to).insert(ZKANote::new(asset_commitment, value)).get_new_note();
        let output_note_hash = output.note.zka_note_hash(output.owner, output.randomness);
        NoteMessage::new(output, self.context).deliver(MessageDelivery::onchain_constrained());

        let receipt = ZKAPayReceiptV1::new(interaction_context, output_note_hash, self.address);
        self.emit(receipt).deliver_to(to, MessageDelivery::onchain_constrained());
        self.internal._return_change(from, asset_commitment, change);
    }

    /// Unconditional direct-owner exit to a 20-byte L1 address.
    #[external("private")]
    fn withdraw(amount: Field, asset_commitment: Field, external_recipient: Field) {
        assert(amount != 0, "Withdrawal amount must be non-zero");
        assert(external_recipient != 0, "External recipient must be non-zero");
        crate::withdrawal::assert_fits_u160(external_recipient);
        self.internal._assert_asset(asset_commitment);
        let from = self.msg_sender();
        let change = self.call_self._spend(from, asset_commitment, amount);
        self.internal._return_change(from, asset_commitment, change);
        self.enqueue_self._process_withdrawal(external_recipient, amount);
    }

    #[external("public")]
    #[only_self]
    fn _process_withdrawal(external_recipient: Field, amount: Field) {
        assert(amount != 0, "Withdrawal amount must be non-zero");
        assert(external_recipient != 0, "External recipient must be non-zero");
        crate::withdrawal::assert_fits_u160(external_recipient);
        let portal = self.storage.portal.read();
        let content = crate::withdrawal::withdraw_content_hash(external_recipient, amount);
        self.context.message_portal(portal, content);
    }

    #[internal("private")]
    fn _assert_asset(asset_commitment: Field) {
        assert(
            asset_commitment == self.storage.asset_commitment.read(),
            "Asset must match immutable commitment",
        );
    }

    // Every popped note is asset-scoped, checked as u128, and included in the
    // returned change.  Any insufficient-balance result reverts atomically.
    // External only to get its own call frame; `only_self` keeps it unreachable
    // except from the entrypoints that authorize `from`.
    #[external("private")]
    #[only_self]
    fn _spend(from: AztecAddress, asset_commitment: Field, amount: Field) -> Field {
        assert_fits_u128(amount);
        let options = NoteGetterOptions::new()
            .select(ZKANote::properties().asset_commitment, Comparator.EQ, asset_commitment)
            .sort(ZKANote::properties().value, SortOrder.DESC)
            .set_limit(MAX_SPEND_NOTES);
        let notes = self.storage.notes.at(from).pop_notes(options);
        assert(notes.len() > 0, "No notes available for this asset");
        let mut values: [u128; MAX_SPEND_NOTES] = [0; MAX_SPEND_NOTES];
        for i in 0..MAX_SPEND_NOTES {
            if i < notes.len() {
                let note_value = notes.get_unchecked(i).value;
                assert_fits_u128(note_value);
                values[i] = note_value as u128;
            }
        }
        conserved_change(values, notes.len(), amount as u128) as Field
    }

    #[internal("private")]
    fn _return_change(owner: AztecAddress, asset_commitment: Field, change: Field) {
        if change != 0 {
            self.storage.notes.at(owner).insert(ZKANote::new(asset_commitment, change)).deliver(
                MessageDelivery::onchain_constrained(),
            );
        }
    }

    #[external("utility")]
    unconstrained fn get_balance(owner: AztecAddress, asset_commitment: Field) -> pub Field {
        let options = aztec::note::note_viewer_options::NoteViewerOptions::new();
        let notes = self.storage.notes.at(owner).view_notes(options);
        let mut balance: Field = 0;
        for i in 0..notes.len() {
            let note = notes.get_unchecked(i);
            if note.asset_commitment == asset_commitment {
                balance += note.value;
            }
        }
        balance
    }

    /// Decode exactly one canonical private-log ciphertext under the recipient's
    /// PXE scope. The holder must supply the 15 ciphertext fields from a pinned
    /// tx effect's private_logs[index] and independently verify its event
    /// commitment/nullifier. This utility never returns generic plaintext.
    #[external("utility")]
    unconstrained fn decode_receipt_log(
        recipient: AztecAddress,
        ciphertext: [Field; MESSAGE_CIPHERTEXT_LEN],
    ) -> pub [Field; 6] {
        assert(!recipient.is_zero(), "Receipt recipient must be non-zero");
        let decrypted =
            AES128::decrypt(BoundedVec::from_array(ciphertext), recipient, self.address);
        assert(decrypted.is_some(), "Receipt ciphertext cannot be decrypted");
        let message = decode_message(decrypted.unwrap());
        assert(message.is_some(), "Receipt message encoding is invalid");
        let (message_type, metadata, content) = message.unwrap();
        assert(message_type == PRIVATE_EVENT_MSG_TYPE_ID, "Receipt message type is invalid");
        assert(
            metadata == ZKAPayReceiptV1::get_event_type_id().to_field() as u64,
            "Receipt event selector is invalid",
        );
        assert(content.len() == 6, "Receipt content length is invalid");
        assert(content.get(1) == ZKA_PAY_RECEIPT_V1_DOMAIN, "Receipt domain is invalid");
        assert(content.get(2) == ZKA_PAY_RECEIPT_V1_VERSION, "Receipt version is invalid");
        assert(content.get(3) != 0, "Receipt context must be non-zero");
        assert(content.get(5) == self.address.to_field(), "Receipt contract instance is invalid");
        [
            content.get(0),
            content.get(1),
            content.get(2),
            content.get(3),
            content.get(4),
            content.get(5),
        ]
    }
}
