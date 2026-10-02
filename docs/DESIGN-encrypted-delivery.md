# Automatic encrypted delivery for Probant

Status: proposed, 2 October 2026. The current client writes a local share file;
there is no server mailbox or automatic recipient polling yet.

## User flow

1. A recipient enables receiving on their installation. Their public card is
   registered with proof that they possess its signing key. Private keys stay local.
2. The sender selects matters and an existing, confirmed contact. Marks remain
   excluded unless the sender selects Include my marks.
3. The client signs and encrypts the share locally using the existing share format.
   It saves the local copy before uploading encrypted bytes to the mailbox service.
4. The page says Queued only after the server acknowledges storage. Failure leaves
   the local file available for retry or manual transfer; it never says Sent on failure.
5. While Probant home is running, the recipient checks for new deliveries. It
   downloads encrypted files into a private local directory and displays a pending
   delivery. Downloading does not start an AI session or create matters.
6. The recipient opens the pending delivery. Decryption and signature checks run
   locally; the recipient reviews the contents and chooses to import them.

Receiving with an InferRoute account versus receiving with the key alone is an
open product choice. Account-based receiving uses the verified account email.
Key-only receiving requires separate email verification and notification consent.
Neither mode may derive an email address from a public key or trust an email
address entered by the sender as the recipient's verified address.

## Identity and routing

- Route by a domain-separated SHA-256 identifier of both full public keys, rather
  than by the short fingerprint displayed to people.
- Registration signs a short-lived, single-use server challenge covering protocol
  version, operation, complete public card and account identity when applicable.
- Authenticate uploads and reads, enforce per-account and per-mailbox quotas, and
  require a receiving identity to prove possession before it can read a mailbox.
- The sender encrypts to the public key already saved in their contacts. A server
  directory must never silently replace that key.
- Verify the encrypted payload's signature locally. For a known sender fingerprint,
  also compare the signing public key with the saved contact's signing key before
  treating the sender as known. A signed, self-asserted fingerprint is insufficient.
- Unknown senders remain explicitly unknown until independently confirmed.

## Backend

The service stores encrypted envelopes, opaque delivery identifiers, ciphertext
hashes for idempotency, routing identifiers, timestamps and transfer status. It
does not receive matter titles, disclosures, notes, marks, document names, private
keys or plaintext hashes as separate metadata fields.

The existing envelope exposes recipient fingerprints. It remains encrypted
content, but is not metadata-free. The service also sees sender/recipient linkage,
IP addresses, delivery times and sizes. These limits belong in the sharing UI and
the published privacy claim.

Proposed defaults: 30-day server retention, bounded upload sizes, storage quotas,
bounded polling with backoff and jitter, and a durable notification outbox. Limits
must be enforced by the server before storing an upload. Expiration removes the
server copy; it cannot withdraw a copy the recipient already downloaded.

Uploads need idempotent retry without duplicate deliveries. A downloaded
acknowledgement follows durable local storage. Opened/imported status is separate
and must not be reported as the recipient having read the contents.

Do not log request bodies or route these requests through AI conversation logging.
The mailbox is an ordinary ciphertext relay, outside the attested AI/search lanes.
Existing signatures still authenticate payloads; this service adds transport, not
new attestation of the sharing operation or proof of timely delivery.

## Email notification

- Notification is optional and uses the recipient's verified address and preference.
- Generic subject/body: A new encrypted delivery is available in Probant.
- No matter names, notes, sender-provided text, documents, keys, decryption links,
  bearer tokens or encrypted attachments in the email.
- A fixed InferRoute link may explain how to open Probant. Receiving does not depend
  on clicking the email, and email does not prove sender identity.
- Queue notification only after durable mailbox storage; retry with an idempotent
  outbox and suppress repeated notifications for the same pending delivery.
- Email provider failure must not undo or falsely reject a stored delivery. Show
  notification status separately from delivery status.

## Compatibility and rollout

Manual .probant-share transfer remains available. Existing files stay readable.
An unregistered recipient needs an explicit setup message and manual fallback;
the sender must not be told their share is available remotely when it is not.

This needs client changes, backend endpoints and storage, an email provider,
receiving setup and updated privacy wording. Production mail/storage credentials
and service deployment are not supplied by the existing client wheel release.
