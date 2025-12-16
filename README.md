# Passkey-Gated DAO Treasury

Multi-sig DAO treasury where signers authenticate with passkeys (WebAuthn) instead of traditional wallets. No seed phrases, maximum security.

## Clarity 4 Features Used

| Feature | Usage |
|---------|-------|
| `secp256r1-verify` | Verify passkey signatures for proposal approvals |
| `stacks-block-time` | Proposal voting periods, execution timelocks |
| `contract-hash?` | Verify execution target contracts |
| `to-ascii?` | Generate proposal summaries and signer info |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Signer Registry                           │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Passkey public keys (secp256r1)                     │   │
│  │  Activity tracking & reputation                       │   │
│  │  Inactivity detection                                │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   Treasury Manager                           │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  secp256r1-verify → Verify passkey signatures        │   │
│  │  create-proposal → Propose treasury actions          │   │
│  │  approve-proposal → Multi-sig approval               │   │
│  │  stacks-block-time → Timelock enforcement            │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   Proposal Engine                            │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  contract-hash? → Verify execution targets            │   │
│  │  Record execution history                            │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Why Passkeys?

| Feature | Traditional Wallet | Passkey Treasury |
|---------|-------------------|------------------|
| Authentication | Seed phrase | Biometric/PIN |
| Key Storage | User responsibility | Hardware secure element |
| Backup | Write down 24 words | Cloud sync (optional) |
| Phishing Risk | High | None (origin-bound) |
| Device Support | Wallet apps | Built into OS |

## How It Works

1. **Setup**: Admin adds signers with their passkey public keys
2. **Propose**: Signer creates proposal with passkey signature
3. **Approve**: Other signers approve with their passkeys
4. **Timelock**: After threshold reached, 24hr delay
5. **Execute**: Anyone can trigger execution after timelock

## Proposal Types

| Type | Description | Example |
|------|-------------|---------|
| Transfer | Send STX from treasury | Pay contractor 1000 STX |
| Add Signer | Add new passkey signer | Onboard new team member |
| Remove Signer | Remove signer access | Offboard former employee |
| Change Threshold | Modify approval requirement | 2/3 → 3/5 |
| Contract Call | Execute verified contract | Invest in DeFi protocol |

## Contract Functions

### Signer Management

```clarity
;; Add initial signer (setup)
(add-initial-signer
    (passkey-pubkey-x (buff 32))
    (passkey-pubkey-y (buff 32))
    (name (string-ascii 64)))

;; Rotate your passkey
(rotate-passkey
    (signer-id uint)
    (new-pubkey-x (buff 32))
    (new-pubkey-y (buff 32))
    (old-signature (buff 64))
    (nonce uint))
```

### Proposals

```clarity
;; Create transfer proposal
(create-transfer-proposal
    (title (string-ascii 128))
    (description (string-ascii 256))
    (recipient principal)
    (amount uint)
    (signer-id uint)
    (signature (buff 64))
    (nonce uint))

;; Approve with passkey
(approve-proposal
    (proposal-id uint)
    (signer-id uint)
    (signature (buff 64))
    (nonce uint))

;; Execute after timelock
(execute-proposal (proposal-id uint))
```

### Read-Only Helpers

```clarity
;; Verify passkey signature
(verify-passkey-signature
    (signer-id uint)
    (message-hash (buff 32))
    (signature (buff 64)))

;; Generate approval message for signing
(generate-approval-message
    (proposal-id uint)
    (signer-id uint)
    (nonce uint))

;; Get proposal summary
(generate-proposal-summary (proposal-id uint))
;; Returns: "Proposal #1: Fund Development | Amount: 100000000 | Approvals: 2/3"

;; Check if ready to execute
(can-execute (proposal-id uint))
```

## Signature Verification

Using WebAuthn's secp256r1 (P-256) curve:

```clarity
;; Verify signature using Clarity 4's secp256r1-verify
(secp256r1-verify 
    message-hash      ;; SHA256 of proposal data
    signature         ;; 64-byte ECDSA signature
    public-key        ;; 64-byte uncompressed public key (x || y)
)
```

## Message Format

For signing proposals:

```
message = SHA256(
    proposal-id ||
    signer-id ||
    nonce ||
    treasury-nonce
)
```

## Security Features

1. **Passkey Auth**: Hardware-backed, phishing-resistant
2. **Nonce System**: Replay attack protection
3. **Timelock**: 24hr delay after approval threshold
4. **Contract Verification**: `contract-hash?` on execution targets
5. **Inactivity Detection**: Flag inactive signers

## Installation & Testing

```bash
cd passkey-dao-treasury
clarinet check
clarinet test
```

## Example: Create and Approve Transfer

```typescript
// 1. Setup treasury with 3 signers
await addInitialSigner({
    pubkeyX: alicePubkeyX,
    pubkeyY: alicePubkeyY,
    name: "Alice"
});
// ... add Bob and Charlie

// 2. Set 2/3 threshold
await setThreshold(2);

// 3. Deposit funds
await deposit(1000000000); // 1000 STX

// 4. Alice creates proposal
const nonce = await getSignerNonce(1);
const message = await generateApprovalMessage(0, 1, nonce);
const signature = await signWithPasskey(message, aliceCredential);

const proposalId = await createTransferProposal({
    title: "Pay Developer",
    description: "Monthly payment for frontend work",
    recipient: developerAddress,
    amount: 100000000, // 100 STX
    signerId: 1,
    signature: signature,
    nonce: nonce
});

// 5. Bob approves
const bobNonce = await getSignerNonce(2);
const bobMessage = await generateApprovalMessage(proposalId, 2, bobNonce);
const bobSig = await signWithPasskey(bobMessage, bobCredential);

await approveProposal({
    proposalId: proposalId,
    signerId: 2,
    signature: bobSig,
    nonce: bobNonce
});

// 6. Wait 24 hours (timelock)
// ...

// 7. Execute
await executeProposal(proposalId);
```

## Proposal Lifecycle

```
PENDING → APPROVED → EXECUTED
   ↓         ↓
   └── EXPIRED ←──┘
         ↓
      CANCELLED
```

## Integration with WebAuthn

Frontend implementation (conceptual):

```javascript
// Register new passkey
const credential = await navigator.credentials.create({
    publicKey: {
        challenge: randomBytes(32),
        rp: { name: "DAO Treasury" },
        user: { id: signerId, name: "Alice" },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }], // ES256
        authenticatorSelection: {
            authenticatorAttachment: "platform",
            userVerification: "required"
        }
    }
});

// Extract public key for contract
const publicKey = credential.response.getPublicKey();
const pubkeyX = publicKey.slice(0, 32);
const pubkeyY = publicKey.slice(32, 64);

// Sign approval
const assertion = await navigator.credentials.get({
    publicKey: {
        challenge: messageHash,
        allowCredentials: [{ type: "public-key", id: credentialId }]
    }
});

const signature = assertion.response.signature;
```

## Hiro Chainhooks Integration

Real-time event monitoring for the Passkey DAO Treasury using Hiro Chainhooks.

### Features

The chainhooks integration monitors:
- Proposal creation and approvals
- Vote submissions with passkey authentication
- Proposal executions
- Treasury deposit and transfer operations
- Signer management events (add/remove/rotate keys)

### Setup

```bash
cd chainhooks
npm install
cp .env.example .env
# Edit .env with your configuration
npm start
```

### Monitored Events

- **Proposal Created**: New treasury proposals
- **Proposal Approved**: Signer approvals with passkey signatures
- **Proposal Executed**: Successful proposal execution
- **Treasury Operations**: STX deposits and transfers
- **Passkey Authentication**: Signature verification events
- **Signer Management**: Adding/removing/rotating passkeys

See `chainhooks/README.md` for detailed setup instructions and event handling.

## License

MIT License
