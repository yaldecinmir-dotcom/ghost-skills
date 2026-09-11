# Binding a receipt to one payment: design only, not implemented

Nothing here is built and production is unchanged. This answers "what would make a receipt
evidence of *this* payment rather than *a* payment", so the design can be reviewed before
any code exists.

## What today's identifiers do and do not do

`receipt_id` and `operation_id` make two otherwise identical searches distinguishable.
That is all they do. **Neither is payment evidence.** A seller mints both and can mint
as many as it likes, so on their own they establish nothing about money. Ghost's verifier
prints them under a label that says so.

## The four things that would have to be tied together

For an x402 `exact` payment on Base the chain of custody has four links, and a receipt is
only evidence of a specific purchase if it binds all four into the signed statement.

1. **The payment requirement digest.** The seller's 402 carries `accepts[]` with scheme,
   network, asset, amount, `payTo` and `maxTimeoutSeconds`. Hash the exact requirement
   object the buyer was served, canonically, and sign that digest. Without it the receipt
   cannot say which offer was accepted, only that some offer existed.
2. **The payment payload digest.** The buyer returns a signed EIP-3009
   `TransferWithAuthorization`. Hash the payload as transmitted, and sign the digest, never
   the payload: the authorization is bearer-ish material until it is spent, and a receipt
   is a document that gets forwarded.
3. **The authorization nonce and payer.** EIP-3009 carries a 32-byte `nonce` unique per
   authorization, plus `from`. These are the only fields that are unique to one payment
   *and* verifiable on-chain by a third party. Signing `payer` and `nonce` is what makes
   the receipt non-replayable: a second receipt reusing the same nonce is provably the same
   payment, and the same nonce cannot settle twice because the token contract rejects it.
4. **The settlement transaction.** Hash plus log index, so a verifier can fetch exactly one
   `Transfer` event and compare `from`, `to`, `value` and the contract address.

## What the verifier would then be able to say

With 1 to 4 bound, and only then:

- the requirement the buyer signed is the one the seller advertised, link 1 against the
  buyer's own copy of the 402;
- the authorization the buyer produced is the one that settled, link 2 and 3 against link 4
  by reading the nonce out of the transaction's calldata;
- the delivery in hand is the one paid for, link 3 against the existing request and
  response commitments;
- and the receipt cannot be replayed for a second purchase, because the nonce is spent.

## Ordering problem, stated rather than waved away

The seller signs the receipt when it delivers. Settlement may confirm later. So the receipt
can bind links 1 to 3 truthfully at signing time, and link 4 only as a *claimed* reference
whose confirmation the verifier must do itself. That is exactly why `SETTLED` is not a
signable state. A seller that waits for confirmation before signing has the opposite
problem: it must hold the delivery, and a buyer that disconnects gets nothing while having
paid. Signing early with an explicit CLAIMED state is the honest trade.

## Double-spend and replay, as separate concerns

- **Receipt replay:** presenting one receipt as evidence of two purchases. Closed by
  binding the nonce, which is unique per authorization.
- **Authorization double-spend:** presenting one signed authorization twice. Closed by the
  USDC contract, not by Ghost. The receipt inherits that guarantee only by naming the nonce.
- **Delivery replay:** presenting an old delivery as a fresh one. Closed by `signed_at`
  plus the freshness window a verifier chooses. Ghost does not impose one, because the
  acceptable window is the buyer's risk decision rather than the seller's.
