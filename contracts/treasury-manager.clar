;; treasury-manager.clar
;; Multi-sig DAO treasury with passkey (WebAuthn/secp256r1) authentication
;; Uses Clarity 4 features: secp256r1-verify, stacks-block-time, contract-hash?, to-ascii?

;; ========================================
;; Constants
;; ========================================

(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR_NOT_AUTHORIZED (err u17001))
(define-constant ERR_INVALID_SIGNATURE (err u17002))
(define-constant ERR_PROPOSAL_NOT_FOUND (err u17003))
(define-constant ERR_PROPOSAL_EXPIRED (err u17004))
(define-constant ERR_ALREADY_APPROVED (err u17005))
(define-constant ERR_NOT_ENOUGH_APPROVALS (err u17006))
(define-constant ERR_PROPOSAL_EXECUTED (err u17007))
(define-constant ERR_INVALID_NONCE (err u17008))
(define-constant ERR_SIGNER_NOT_FOUND (err u17009))
(define-constant ERR_TIMELOCK_ACTIVE (err u17010))
(define-constant ERR_INSUFFICIENT_FUNDS (err u17011))
(define-constant ERR_DELEGATION_NOT_FOUND (err u17012))
(define-constant ERR_CANNOT_DELEGATE_TO_SELF (err u17013))
(define-constant ERR_DELEGATION_EXPIRED (err u17014))
(define-constant ERR_ALREADY_VOTED (err u17015))
(define-constant ERR_BATCH_TOO_LARGE (err u17016))
(define-constant ERR_BATCH_EXECUTION_FAILED (err u17017))
(define-constant ERR_TEMPLATE_NOT_FOUND (err u17018))
(define-constant ERR_TEMPLATE_EXISTS (err u17019))

;; Proposal status
(define-constant STATUS_PENDING u0)
(define-constant STATUS_APPROVED u1)
(define-constant STATUS_EXECUTED u2)
(define-constant STATUS_CANCELLED u3)
(define-constant STATUS_EXPIRED u4)

;; Proposal types
(define-constant PROPOSAL_TRANSFER u0)
(define-constant PROPOSAL_ADD_SIGNER u1)
(define-constant PROPOSAL_REMOVE_SIGNER u2)
(define-constant PROPOSAL_CHANGE_THRESHOLD u3)
(define-constant PROPOSAL_CONTRACT_CALL u4)
(define-constant PROPOSAL_BATCH_TRANSFER u5)

;; Default timelock: 24 hours
(define-constant DEFAULT_TIMELOCK u86400)

;; ========================================
;; Data Variables
;; ========================================

(define-data-var proposal-counter uint u0)
(define-data-var signer-count uint u0)
(define-data-var approval-threshold uint u2)
(define-data-var timelock-duration uint DEFAULT_TIMELOCK)
(define-data-var treasury-nonce uint u0)
(define-data-var contract-principal principal tx-sender)
(define-data-var delegation-enabled bool true)
(define-data-var total-delegations uint u0)
(define-data-var template-counter uint u0)
(define-data-var total-batch-transfers uint u0)
(define-data-var total-batch-recipients uint u0)

;; ========================================
;; Data Maps
;; ========================================

;; Signers with passkey public keys (compressed format for secp256r1)
(define-map signers
    uint
    {
        passkey-pubkey: (buff 33),
        name: (string-ascii 64),
        added-at: uint,
        last-activity: uint,
        proposals-created: uint,
        proposals-approved: uint,
        active: bool
    }
)

;; Lookup signer by public key hash
(define-map signer-by-pubkey
    (buff 32)
    uint
)

;; Proposals
(define-map proposals
    uint
    {
        title: (string-ascii 128),
        description: (string-ascii 256),
        proposal-type: uint,
        creator-signer-id: uint,
        target-contract: (optional principal),
        target-function: (optional (string-ascii 64)),
        recipient: (optional principal),
        amount: uint,
        execution-data: (optional (buff 256)),
        created-at: uint,
        expires-at: uint,
        execution-time: (optional uint),
        approval-count: uint,
        status: uint
    }
)

;; Track approvals per proposal
(define-map proposal-approvals
    { proposal-id: uint, signer-id: uint }
    {
        approved-at: uint,
        signature-hash: (buff 32)
    }
)

;; Nonces per signer (replay protection)
(define-map signer-nonces
    uint
    uint
)

;; Delegation system
(define-map delegations
    { delegator-id: uint, delegate-id: uint }
    {
        created-at: uint,
        expires-at: (optional uint),
        proposals-delegated: uint,
        active: bool
    }
)

;; Track delegated votes per proposal
(define-map delegated-votes
    { proposal-id: uint, delegate-id: uint, delegator-id: uint }
    {
        voted-at: uint,
        signature-hash: (buff 32)
    }
)

;; Batch transfer recipients (indexed by proposal-id and recipient-index)
(define-map batch-recipients
    { proposal-id: uint, index: uint }
    {
        recipient: principal,
        amount: uint,
        executed: bool
    }
)

;; Track batch size per proposal
(define-map batch-sizes
    uint
    uint
)

;; Proposal templates
(define-map proposal-templates
    uint
    {
        name: (string-ascii 64),
        description: (string-ascii 256),
        template-type: uint,
        created-by: uint,
        created-at: uint,
        times-used: uint,
        active: bool
    }
)

;; Template batch recipients (for reusable templates)
(define-map template-batch-recipients
    { template-id: uint, index: uint }
    {
        recipient: principal,
        amount: uint
    }
)

(define-map template-batch-sizes
    uint
    uint
)

;; ========================================
;; Read-Only Functions
;; ========================================

(define-read-only (get-current-time)
    stacks-block-time
)

(define-read-only (get-signer (signer-id uint))
    (map-get? signers signer-id)
)

(define-read-only (get-proposal (proposal-id uint))
    (map-get? proposals proposal-id)
)

(define-read-only (get-treasury-balance)
    (stx-get-balance (var-get contract-principal))
)

(define-read-only (get-signer-nonce (signer-id uint))
    (default-to u0 (map-get? signer-nonces signer-id))
)

(define-read-only (get-approval-threshold)
    (var-get approval-threshold)
)

(define-read-only (get-signer-count)
    (var-get signer-count)
)

;; Check if signer has approved proposal
(define-read-only (has-approved (proposal-id uint) (signer-id uint))
    (is-some (map-get? proposal-approvals { proposal-id: proposal-id, signer-id: signer-id }))
)

;; Check if proposal can be executed
(define-read-only (can-execute (proposal-id uint))
    (match (map-get? proposals proposal-id)
        proposal (and
            (is-eq (get status proposal) STATUS_APPROVED)
            (match (get execution-time proposal)
                exec-time (<= exec-time stacks-block-time)
                false
            )
        )
        false
    )
)

;; Generate proposal summary using to-ascii?
(define-read-only (generate-proposal-summary (proposal-id uint))
    (match (map-get? proposals proposal-id)
        proposal (let
            (
                (id-str (unwrap-panic (to-ascii? proposal-id)))
                (amount-str (unwrap-panic (to-ascii? (get amount proposal))))
                (approvals-str (unwrap-panic (to-ascii? (get approval-count proposal))))
                (threshold-str (unwrap-panic (to-ascii? (var-get approval-threshold))))
            )
            (concat 
                (concat (concat "Proposal #" id-str) (concat ": " (get title proposal)))
                (concat (concat " | Amount: " amount-str)
                    (concat (concat " | Approvals: " approvals-str)
                        (concat "/" threshold-str)
                    )
                )
            )
        )
        "Proposal not found"
    )
)

;; Delegation read-only functions
(define-read-only (get-delegation (delegator-id uint) (delegate-id uint))
    (map-get? delegations { delegator-id: delegator-id, delegate-id: delegate-id }))

(define-read-only (is-delegation-active (delegator-id uint) (delegate-id uint))
    (match (map-get? delegations { delegator-id: delegator-id, delegate-id: delegate-id })
        delegation (and (get active delegation)
                       (match (get expires-at delegation)
                           expiry (< stacks-block-time expiry)
                           true))
        false))

(define-read-only (has-delegated-vote (proposal-id uint) (delegate-id uint) (delegator-id uint))
    (is-some (map-get? delegated-votes { proposal-id: proposal-id, delegate-id: delegate-id, delegator-id: delegator-id })))

;; Batch transfer read-only functions
(define-read-only (get-batch-recipient (proposal-id uint) (index uint))
    (map-get? batch-recipients { proposal-id: proposal-id, index: index }))

(define-read-only (get-batch-size (proposal-id uint))
    (default-to u0 (map-get? batch-sizes proposal-id)))

;; Template read-only functions
(define-read-only (get-template (template-id uint))
    (map-get? proposal-templates template-id))

(define-read-only (get-template-batch-recipient (template-id uint) (index uint))
    (map-get? template-batch-recipients { template-id: template-id, index: index }))

(define-read-only (get-template-batch-size (template-id uint))
    (default-to u0 (map-get? template-batch-sizes template-id)))

;; Get batch transfer statistics
(define-read-only (get-batch-stats)
    {
        total-batch-transfers: (var-get total-batch-transfers),
        total-recipients: (var-get total-batch-recipients),
        total-templates: (var-get template-counter)
    })

;; Generate message hash for signing
(define-read-only (generate-approval-message (proposal-id uint) (signer-id uint) (nonce uint))
    (sha256 (concat
        (concat (unwrap-panic (to-consensus-buff? proposal-id)) (unwrap-panic (to-consensus-buff? signer-id)))
        (concat (unwrap-panic (to-consensus-buff? nonce)) (unwrap-panic (to-consensus-buff? (var-get treasury-nonce))))
    ))
)

;; Verify passkey signature using secp256r1-verify
(define-read-only (verify-passkey-signature
    (signer-id uint)
    (message-hash (buff 32))
    (signature (buff 64)))
    (match (map-get? signers signer-id)
        signer (secp256r1-verify
            message-hash
            signature
            (get passkey-pubkey signer)
        )
        false
    )
)

;; Get treasury stats
(define-read-only (get-treasury-stats)
    {
        balance: (get-treasury-balance),
        total-proposals: (var-get proposal-counter),
        signer-count: (var-get signer-count),
        threshold: (var-get approval-threshold),
        timelock: (var-get timelock-duration),
        nonce: (var-get treasury-nonce)
    }
)

;; ========================================
;; Signer Management
;; ========================================

;; Add initial signer (setup only)
(define-public (add-initial-signer
    (passkey-pubkey (buff 33))
    (name (string-ascii 64)))
    (let
        (
            (signer-id (+ (var-get signer-count) u1))
            (current-time stacks-block-time)
            (pubkey-hash (sha256 passkey-pubkey))
        )
        ;; Only owner can add initial signers
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)

        ;; Add signer
        (map-set signers signer-id {
            passkey-pubkey: passkey-pubkey,
            name: name,
            added-at: current-time,
            last-activity: current-time,
            proposals-created: u0,
            proposals-approved: u0,
            active: true
        })

        ;; Add lookup
        (map-set signer-by-pubkey pubkey-hash signer-id)

        ;; Initialize nonce
        (map-set signer-nonces signer-id u0)

        (var-set signer-count signer-id)

        (ok signer-id)
    )
)

;; Rotate passkey (signer rotates their own key)
(define-public (rotate-passkey
    (signer-id uint)
    (new-pubkey (buff 33))
    (old-signature (buff 64))
    (nonce uint))
    (let
        (
            (signer (unwrap! (map-get? signers signer-id) ERR_SIGNER_NOT_FOUND))
            (current-nonce (get-signer-nonce signer-id))
            (message-hash (sha256 (concat
                new-pubkey
                (unwrap-panic (to-consensus-buff? nonce))
            )))
            (old-pubkey (get passkey-pubkey signer))
            (new-pubkey-hash (sha256 new-pubkey))
            (old-pubkey-hash (sha256 old-pubkey))
        )
        ;; Verify nonce
        (asserts! (is-eq nonce current-nonce) ERR_INVALID_NONCE)

        ;; Verify signature with old key
        (asserts! (secp256r1-verify message-hash old-signature old-pubkey) ERR_INVALID_SIGNATURE)

        ;; Update signer with new key
        (map-set signers signer-id (merge signer {
            passkey-pubkey: new-pubkey,
            last-activity: stacks-block-time
        }))

        ;; Update lookup
        (map-delete signer-by-pubkey old-pubkey-hash)
        (map-set signer-by-pubkey new-pubkey-hash signer-id)

        ;; Increment nonce
        (map-set signer-nonces signer-id (+ current-nonce u1))

        (ok true)
    )
)

;; ========================================
;; Proposal Management
;; ========================================

;; Create transfer proposal
(define-public (create-transfer-proposal
    (title (string-ascii 128))
    (description (string-ascii 256))
    (recipient principal)
    (amount uint)
    (signer-id uint)
    (signature (buff 64))
    (nonce uint))
    (let
        (
            (proposal-id (+ (var-get proposal-counter) u1))
            (current-time stacks-block-time)
            (current-nonce (get-signer-nonce signer-id))
            (signer (unwrap! (map-get? signers signer-id) ERR_SIGNER_NOT_FOUND))
            (message-hash (sha256 (concat
                (concat (unwrap-panic (to-consensus-buff? recipient)) (unwrap-panic (to-consensus-buff? amount)))
                (unwrap-panic (to-consensus-buff? nonce))
            )))
        )
        ;; Verify signer is active
        (asserts! (get active signer) ERR_NOT_AUTHORIZED)
        
        ;; Verify nonce
        (asserts! (is-eq nonce current-nonce) ERR_INVALID_NONCE)
        
        ;; Verify passkey signature
        (asserts! (verify-passkey-signature signer-id message-hash signature) ERR_INVALID_SIGNATURE)
        
        ;; Check sufficient funds
        (asserts! (<= amount (get-treasury-balance)) ERR_INSUFFICIENT_FUNDS)
        
        ;; Create proposal
        (map-set proposals proposal-id {
            title: title,
            description: description,
            proposal-type: PROPOSAL_TRANSFER,
            creator-signer-id: signer-id,
            target-contract: none,
            target-function: none,
            recipient: (some recipient),
            amount: amount,
            execution-data: none,
            created-at: current-time,
            expires-at: (+ current-time (* u7 u86400)), ;; 7 days to approve
            execution-time: none,
            approval-count: u1, ;; Creator auto-approves
            status: STATUS_PENDING
        })
        
        ;; Record creator's approval
        (map-set proposal-approvals { proposal-id: proposal-id, signer-id: signer-id } {
            approved-at: current-time,
            signature-hash: (sha256 signature)
        })
        
        ;; Update signer stats
        (map-set signers signer-id (merge signer {
            last-activity: current-time,
            proposals-created: (+ (get proposals-created signer) u1),
            proposals-approved: (+ (get proposals-approved signer) u1)
        }))
        
        ;; Increment nonce
        (map-set signer-nonces signer-id (+ current-nonce u1))
        
        (var-set proposal-counter proposal-id)
        
        ;; Print proposal summary
        (print (generate-proposal-summary proposal-id))
        
        (ok proposal-id)
    )
)

;; Approve proposal with passkey
(define-public (approve-proposal
    (proposal-id uint)
    (signer-id uint)
    (signature (buff 64))
    (nonce uint))
    (let
        (
            (proposal (unwrap! (map-get? proposals proposal-id) ERR_PROPOSAL_NOT_FOUND))
            (signer (unwrap! (map-get? signers signer-id) ERR_SIGNER_NOT_FOUND))
            (current-time stacks-block-time)
            (current-nonce (get-signer-nonce signer-id))
            (message-hash (generate-approval-message proposal-id signer-id nonce))
            (threshold (var-get approval-threshold))
        )
        ;; Validations
        (asserts! (get active signer) ERR_NOT_AUTHORIZED)
        (asserts! (is-eq (get status proposal) STATUS_PENDING) ERR_PROPOSAL_EXECUTED)
        (asserts! (< current-time (get expires-at proposal)) ERR_PROPOSAL_EXPIRED)
        (asserts! (not (has-approved proposal-id signer-id)) ERR_ALREADY_APPROVED)
        (asserts! (is-eq nonce current-nonce) ERR_INVALID_NONCE)
        
        ;; Verify passkey signature
        (asserts! (verify-passkey-signature signer-id message-hash signature) ERR_INVALID_SIGNATURE)
        
        ;; Record approval
        (map-set proposal-approvals { proposal-id: proposal-id, signer-id: signer-id } {
            approved-at: current-time,
            signature-hash: (sha256 signature)
        })
        
        ;; Update approval count
        (let ((new-count (+ (get approval-count proposal) u1)))
            (map-set proposals proposal-id (merge proposal {
                approval-count: new-count,
                status: (if (>= new-count threshold)
                    STATUS_APPROVED
                    STATUS_PENDING
                ),
                execution-time: (if (>= new-count threshold)
                    (some (+ current-time (var-get timelock-duration)))
                    none
                )
            }))
        )
        
        ;; Update signer stats
        (map-set signers signer-id (merge signer {
            last-activity: current-time,
            proposals-approved: (+ (get proposals-approved signer) u1)
        }))
        
        ;; Increment nonce
        (map-set signer-nonces signer-id (+ current-nonce u1))
        
        ;; Print updated summary
        (print (generate-proposal-summary proposal-id))
        
        (ok true)
    )
)

;; Execute approved proposal (after timelock)
(define-public (execute-proposal (proposal-id uint))
    (let
        (
            (proposal (unwrap! (map-get? proposals proposal-id) ERR_PROPOSAL_NOT_FOUND))
            (current-time stacks-block-time)
            (exec-time (unwrap! (get execution-time proposal) ERR_NOT_ENOUGH_APPROVALS))
        )
        ;; Validations
        (asserts! (is-eq (get status proposal) STATUS_APPROVED) ERR_NOT_ENOUGH_APPROVALS)
        (asserts! (>= current-time exec-time) ERR_TIMELOCK_ACTIVE)
        
        ;; Execute based on proposal type
        (if (is-eq (get proposal-type proposal) PROPOSAL_TRANSFER)
            (begin
                (try! (stx-transfer?
                    (get amount proposal)
                    (var-get contract-principal)
                    (unwrap! (get recipient proposal) ERR_PROPOSAL_NOT_FOUND)
                ))
                (map-set proposals proposal-id (merge proposal { status: STATUS_EXECUTED }))
                (var-set treasury-nonce (+ (var-get treasury-nonce) u1))
                (ok true)
            )
            (ok false) ;; Other types not implemented yet
        )
    )
)

;; Delegate voting power
(define-public (delegate-voting-power
    (delegator-id uint)
    (delegate-id uint)
    (duration (optional uint))
    (signature (buff 64)))
    (let
        (
            (delegator (unwrap! (map-get? signers delegator-id) ERR_SIGNER_NOT_FOUND))
            (delegate (unwrap! (map-get? signers delegate-id) ERR_SIGNER_NOT_FOUND))
            (current-time stacks-block-time)
            (expires-at (match duration
                d (some (+ current-time d))
                none))
            (message-hash (sha256 (concat
                (concat (unwrap-panic (to-consensus-buff? delegator-id)) (unwrap-panic (to-consensus-buff? delegate-id)))
                (unwrap-panic (to-consensus-buff? current-time)))))
        )
        ;; Validations
        (asserts! (var-get delegation-enabled) ERR_NOT_AUTHORIZED)
        (asserts! (not (is-eq delegator-id delegate-id)) ERR_CANNOT_DELEGATE_TO_SELF)
        (asserts! (get active delegator) ERR_NOT_AUTHORIZED)
        (asserts! (get active delegate) ERR_NOT_AUTHORIZED)
        (asserts! (verify-passkey-signature delegator-id message-hash signature) ERR_INVALID_SIGNATURE)

        ;; Create or update delegation
        (map-set delegations { delegator-id: delegator-id, delegate-id: delegate-id } {
            created-at: current-time,
            expires-at: expires-at,
            proposals-delegated: u0,
            active: true
        })

        (var-set total-delegations (+ (var-get total-delegations) u1))

        ;; Emit event
        (print {
            event: "delegation-created",
            delegator-id: delegator-id,
            delegate-id: delegate-id,
            expires-at: expires-at,
            timestamp: current-time
        })

        (ok true)))

;; Revoke delegation
(define-public (revoke-delegation
    (delegator-id uint)
    (delegate-id uint)
    (signature (buff 64)))
    (let
        (
            (delegation (unwrap! (map-get? delegations { delegator-id: delegator-id, delegate-id: delegate-id }) ERR_DELEGATION_NOT_FOUND))
            (delegator (unwrap! (map-get? signers delegator-id) ERR_SIGNER_NOT_FOUND))
            (current-time stacks-block-time)
            (message-hash (sha256 (concat
                (concat (unwrap-panic (to-consensus-buff? delegator-id)) (unwrap-panic (to-consensus-buff? delegate-id)))
                (concat (unwrap-panic (to-consensus-buff? current-time)) (unwrap-panic (to-consensus-buff? u0))))))
        )
        ;; Validations
        (asserts! (get active delegation) ERR_DELEGATION_NOT_FOUND)
        (asserts! (verify-passkey-signature delegator-id message-hash signature) ERR_INVALID_SIGNATURE)

        ;; Deactivate delegation
        (map-set delegations { delegator-id: delegator-id, delegate-id: delegate-id }
            (merge delegation { active: false }))

        ;; Emit event
        (print {
            event: "delegation-revoked",
            delegator-id: delegator-id,
            delegate-id: delegate-id,
            timestamp: current-time
        })

        (ok true)))

;; Approve proposal on behalf of delegator
(define-public (approve-with-delegation
    (proposal-id uint)
    (delegate-id uint)
    (delegator-id uint)
    (signature (buff 64)))
    (let
        (
            (proposal (unwrap! (map-get? proposals proposal-id) ERR_PROPOSAL_NOT_FOUND))
            (delegate (unwrap! (map-get? signers delegate-id) ERR_SIGNER_NOT_FOUND))
            (delegator (unwrap! (map-get? signers delegator-id) ERR_SIGNER_NOT_FOUND))
            (delegation (unwrap! (map-get? delegations { delegator-id: delegator-id, delegate-id: delegate-id }) ERR_DELEGATION_NOT_FOUND))
            (current-time stacks-block-time)
            (nonce (get-signer-nonce delegate-id))
            (message-hash (generate-approval-message proposal-id delegate-id nonce))
        )
        ;; Validations
        (asserts! (is-eq (get status proposal) STATUS_PENDING) ERR_PROPOSAL_EXECUTED)
        (asserts! (< current-time (get expires-at proposal)) ERR_PROPOSAL_EXPIRED)
        (asserts! (is-delegation-active delegator-id delegate-id) ERR_DELEGATION_EXPIRED)
        (asserts! (not (has-approved proposal-id delegator-id)) ERR_ALREADY_VOTED)
        (asserts! (not (has-delegated-vote proposal-id delegate-id delegator-id)) ERR_ALREADY_VOTED)
        (asserts! (verify-passkey-signature delegate-id message-hash signature) ERR_INVALID_SIGNATURE)

        ;; Record delegated approval
        (map-set proposal-approvals { proposal-id: proposal-id, signer-id: delegator-id } {
            approved-at: current-time,
            signature-hash: message-hash
        })

        ;; Track delegated vote
        (map-set delegated-votes { proposal-id: proposal-id, delegate-id: delegate-id, delegator-id: delegator-id } {
            voted-at: current-time,
            signature-hash: message-hash
        })

        ;; Update delegation stats
        (map-set delegations { delegator-id: delegator-id, delegate-id: delegate-id }
            (merge delegation {
                proposals-delegated: (+ (get proposals-delegated delegation) u1)
            }))

        ;; Update proposal
        (let ((new-approval-count (+ (get approval-count proposal) u1)))
            (map-set proposals proposal-id (merge proposal {
                approval-count: new-approval-count,
                status: (if (>= new-approval-count (var-get approval-threshold))
                           STATUS_APPROVED
                           STATUS_PENDING)
            }))

            ;; Emit event
            (print {
                event: "proposal-approved-delegated",
                proposal-id: proposal-id,
                delegate-id: delegate-id,
                delegator-id: delegator-id,
                approval-count: new-approval-count,
                threshold: (var-get approval-threshold),
                status: (if (>= new-approval-count (var-get approval-threshold)) "approved" "pending"),
                timestamp: current-time
            })

            (ok true))))

;; Toggle delegation feature (admin only)
(define-public (toggle-delegation)
    (begin
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
        (var-set delegation-enabled (not (var-get delegation-enabled)))
        (print {
            event: "delegation-toggled",
            enabled: (var-get delegation-enabled),
            timestamp: stacks-block-time
        })
        (ok (var-get delegation-enabled))))

;; ========================================
;; Admin Functions
;; ========================================

;; Set approval threshold
(define-public (set-threshold (new-threshold uint))
    (begin
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
        (asserts! (> new-threshold u0) ERR_NOT_AUTHORIZED)
        (asserts! (<= new-threshold (var-get signer-count)) ERR_NOT_AUTHORIZED)
        (var-set approval-threshold new-threshold)
        (ok true)
    )
)

;; Set timelock duration
(define-public (set-timelock (new-timelock uint))
    (begin
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
        (var-set timelock-duration new-timelock)
        (ok true)
    )
)

;; Deposit to treasury
(define-public (deposit (amount uint))
    (stx-transfer? amount tx-sender (var-get contract-principal))
)

;; ========================================
;; Batch Transfer Functions
;; ========================================

;; Helper: Process single batch transfer
(define-private (execute-batch-item (item { proposal-id: uint, index: uint }) (state { success: bool, total-transferred: uint }))
    (if (get success state)
        (match (map-get? batch-recipients { proposal-id: (get proposal-id item), index: (get index item) })
            recipient-data
                (if (get executed recipient-data)
                    state  ;; Already executed, skip
                    (match (stx-transfer?
                                (get amount recipient-data)
                                (var-get contract-principal)
                                (get recipient recipient-data))
                        ok-result
                            (begin
                                ;; Mark as executed
                                (map-set batch-recipients
                                    { proposal-id: (get proposal-id item), index: (get index item) }
                                    (merge recipient-data { executed: true }))
                                ;; Update state
                                {
                                    success: true,
                                    total-transferred: (+ (get total-transferred state) (get amount recipient-data))
                                })
                        err-result
                            { success: false, total-transferred: (get total-transferred state) }))
            state)  ;; Recipient not found, continue
        state))

;; Create batch transfer proposal
(define-public (create-batch-transfer-proposal
    (title (string-ascii 128))
    (description (string-ascii 256))
    (recipients (list 20 { recipient: principal, amount: uint }))
    (signer-id uint)
    (signature (buff 64))
    (nonce uint))
    (let
        (
            (proposal-id (+ (var-get proposal-counter) u1))
            (current-time stacks-block-time)
            (current-nonce (get-signer-nonce signer-id))
            (signer (unwrap! (map-get? signers signer-id) ERR_SIGNER_NOT_FOUND))
            (total-amount (fold + (map get-amount recipients) u0))
            (batch-size (len recipients))
            (message-hash (sha256 (concat
                (concat (unwrap-panic (to-consensus-buff? title)) (unwrap-panic (to-consensus-buff? total-amount)))
                (unwrap-panic (to-consensus-buff? nonce))
            )))
        )
        ;; Validations
        (asserts! (get active signer) ERR_NOT_AUTHORIZED)
        (asserts! (is-eq nonce current-nonce) ERR_INVALID_NONCE)
        (asserts! (verify-passkey-signature signer-id message-hash signature) ERR_INVALID_SIGNATURE)
        (asserts! (> batch-size u0) ERR_BATCH_TOO_LARGE)
        (asserts! (<= batch-size u20) ERR_BATCH_TOO_LARGE)
        (asserts! (<= total-amount (get-treasury-balance)) ERR_INSUFFICIENT_FUNDS)

        ;; Create proposal
        (map-set proposals proposal-id {
            title: title,
            description: description,
            proposal-type: PROPOSAL_BATCH_TRANSFER,
            creator-signer-id: signer-id,
            target-contract: none,
            target-function: none,
            recipient: none,
            amount: total-amount,
            execution-data: none,
            created-at: current-time,
            expires-at: (+ current-time (* u7 u86400)),
            execution-time: none,
            approval-count: u1,
            status: STATUS_PENDING
        })

        ;; Store batch size
        (map-set batch-sizes proposal-id batch-size)

        ;; Store batch recipients
        (fold store-batch-recipient recipients { proposal-id: proposal-id, index: u0 })

        ;; Record creator's approval
        (map-set proposal-approvals { proposal-id: proposal-id, signer-id: signer-id } {
            approved-at: current-time,
            signature-hash: (sha256 signature)
        })

        ;; Update signer stats
        (map-set signers signer-id (merge signer {
            last-activity: current-time,
            proposals-created: (+ (get proposals-created signer) u1),
            proposals-approved: (+ (get proposals-approved signer) u1)
        }))

        ;; Increment nonce
        (map-set signer-nonces signer-id (+ current-nonce u1))
        (var-set proposal-counter proposal-id)

        ;; Emit event
        (print {
            event: "batch-transfer-proposal-created",
            proposal-id: proposal-id,
            signer-id: signer-id,
            batch-size: batch-size,
            total-amount: total-amount,
            timestamp: current-time
        })

        (ok proposal-id)))

;; Helper to get amount from recipient tuple
(define-private (get-amount (recipient { recipient: principal, amount: uint }))
    (get amount recipient))

;; Helper to store batch recipients
(define-private (store-batch-recipient
    (recipient { recipient: principal, amount: uint })
    (state { proposal-id: uint, index: uint }))
    (begin
        (map-set batch-recipients
            { proposal-id: (get proposal-id state), index: (get index state) }
            {
                recipient: (get recipient recipient),
                amount: (get amount recipient),
                executed: false
            })
        (var-set total-batch-recipients (+ (var-get total-batch-recipients) u1))
        { proposal-id: (get proposal-id state), index: (+ (get index state) u1) }))

;; Execute batch transfer proposal
(define-public (execute-batch-proposal (proposal-id uint))
    (let
        (
            (proposal (unwrap! (map-get? proposals proposal-id) ERR_PROPOSAL_NOT_FOUND))
            (current-time stacks-block-time)
            (exec-time (unwrap! (get execution-time proposal) ERR_NOT_ENOUGH_APPROVALS))
            (batch-size (get-batch-size proposal-id))
        )
        ;; Validations
        (asserts! (is-eq (get proposal-type proposal) PROPOSAL_BATCH_TRANSFER) ERR_NOT_AUTHORIZED)
        (asserts! (is-eq (get status proposal) STATUS_APPROVED) ERR_NOT_ENOUGH_APPROVALS)
        (asserts! (>= current-time exec-time) ERR_TIMELOCK_ACTIVE)

        ;; Execute all batch transfers
        (let ((result (fold execute-batch-item
                            (generate-indices batch-size proposal-id)
                            { success: true, total-transferred: u0 })))
            (asserts! (get success result) ERR_BATCH_EXECUTION_FAILED)

            ;; Mark proposal as executed
            (map-set proposals proposal-id (merge proposal { status: STATUS_EXECUTED }))
            (var-set treasury-nonce (+ (var-get treasury-nonce) u1))
            (var-set total-batch-transfers (+ (var-get total-batch-transfers) u1))

            ;; Emit event
            (print {
                event: "batch-transfer-executed",
                proposal-id: proposal-id,
                batch-size: batch-size,
                total-transferred: (get total-transferred result),
                timestamp: current-time
            })

            (ok { batch-size: batch-size, total-transferred: (get total-transferred result) }))))

;; Helper to generate list of indices for batch processing
(define-private (generate-indices (size uint) (proposal-id uint))
    (if (<= size u0)
        (list)
        (if (<= size u5)
            (list
                { proposal-id: proposal-id, index: u0 }
                { proposal-id: proposal-id, index: u1 }
                { proposal-id: proposal-id, index: u2 }
                { proposal-id: proposal-id, index: u3 }
                { proposal-id: proposal-id, index: u4 })
            (if (<= size u10)
                (list
                    { proposal-id: proposal-id, index: u0 }
                    { proposal-id: proposal-id, index: u1 }
                    { proposal-id: proposal-id, index: u2 }
                    { proposal-id: proposal-id, index: u3 }
                    { proposal-id: proposal-id, index: u4 }
                    { proposal-id: proposal-id, index: u5 }
                    { proposal-id: proposal-id, index: u6 }
                    { proposal-id: proposal-id, index: u7 }
                    { proposal-id: proposal-id, index: u8 }
                    { proposal-id: proposal-id, index: u9 })
                (if (<= size u15)
                    (list
                        { proposal-id: proposal-id, index: u0 }
                        { proposal-id: proposal-id, index: u1 }
                        { proposal-id: proposal-id, index: u2 }
                        { proposal-id: proposal-id, index: u3 }
                        { proposal-id: proposal-id, index: u4 }
                        { proposal-id: proposal-id, index: u5 }
                        { proposal-id: proposal-id, index: u6 }
                        { proposal-id: proposal-id, index: u7 }
                        { proposal-id: proposal-id, index: u8 }
                        { proposal-id: proposal-id, index: u9 }
                        { proposal-id: proposal-id, index: u10 }
                        { proposal-id: proposal-id, index: u11 }
                        { proposal-id: proposal-id, index: u12 }
                        { proposal-id: proposal-id, index: u13 }
                        { proposal-id: proposal-id, index: u14 })
                    (list
                        { proposal-id: proposal-id, index: u0 }
                        { proposal-id: proposal-id, index: u1 }
                        { proposal-id: proposal-id, index: u2 }
                        { proposal-id: proposal-id, index: u3 }
                        { proposal-id: proposal-id, index: u4 }
                        { proposal-id: proposal-id, index: u5 }
                        { proposal-id: proposal-id, index: u6 }
                        { proposal-id: proposal-id, index: u7 }
                        { proposal-id: proposal-id, index: u8 }
                        { proposal-id: proposal-id, index: u9 }
                        { proposal-id: proposal-id, index: u10 }
                        { proposal-id: proposal-id, index: u11 }
                        { proposal-id: proposal-id, index: u12 }
                        { proposal-id: proposal-id, index: u13 }
                        { proposal-id: proposal-id, index: u14 }
                        { proposal-id: proposal-id, index: u15 }
                        { proposal-id: proposal-id, index: u16 }
                        { proposal-id: proposal-id, index: u17 }
                        { proposal-id: proposal-id, index: u18 }
                        { proposal-id: proposal-id, index: u19 }))))))

;; ========================================
;; Template Functions
;; ========================================

;; Create reusable proposal template
(define-public (create-proposal-template
    (name (string-ascii 64))
    (description (string-ascii 256))
    (template-type uint)
    (recipients (list 20 { recipient: principal, amount: uint }))
    (signer-id uint)
    (signature (buff 64)))
    (let
        (
            (template-id (+ (var-get template-counter) u1))
            (current-time stacks-block-time)
            (signer (unwrap! (map-get? signers signer-id) ERR_SIGNER_NOT_FOUND))
            (batch-size (len recipients))
            (message-hash (sha256 (concat
                (unwrap-panic (to-consensus-buff? name))
                (unwrap-panic (to-consensus-buff? current-time))
            )))
        )
        ;; Validations
        (asserts! (get active signer) ERR_NOT_AUTHORIZED)
        (asserts! (verify-passkey-signature signer-id message-hash signature) ERR_INVALID_SIGNATURE)
        (asserts! (> batch-size u0) ERR_BATCH_TOO_LARGE)
        (asserts! (<= batch-size u20) ERR_BATCH_TOO_LARGE)

        ;; Create template
        (map-set proposal-templates template-id {
            name: name,
            description: description,
            template-type: template-type,
            created-by: signer-id,
            created-at: current-time,
            times-used: u0,
            active: true
        })

        ;; Store template batch size
        (map-set template-batch-sizes template-id batch-size)

        ;; Store template recipients
        (fold store-template-recipient recipients { template-id: template-id, index: u0 })

        (var-set template-counter template-id)

        ;; Emit event
        (print {
            event: "template-created",
            template-id: template-id,
            name: name,
            template-type: template-type,
            batch-size: batch-size,
            created-by: signer-id,
            timestamp: current-time
        })

        (ok template-id)))

;; Helper to store template recipients
(define-private (store-template-recipient
    (recipient { recipient: principal, amount: uint })
    (state { template-id: uint, index: uint }))
    (begin
        (map-set template-batch-recipients
            { template-id: (get template-id state), index: (get index state) }
            {
                recipient: (get recipient recipient),
                amount: (get amount recipient)
            })
        { template-id: (get template-id state), index: (+ (get index state) u1) }))

;; Create proposal from template
(define-public (create-proposal-from-template
    (template-id uint)
    (title (string-ascii 128))
    (signer-id uint)
    (signature (buff 64))
    (nonce uint))
    (let
        (
            (template (unwrap! (map-get? proposal-templates template-id) ERR_TEMPLATE_NOT_FOUND))
            (proposal-id (+ (var-get proposal-counter) u1))
            (current-time stacks-block-time)
            (current-nonce (get-signer-nonce signer-id))
            (signer (unwrap! (map-get? signers signer-id) ERR_SIGNER_NOT_FOUND))
            (batch-size (get-template-batch-size template-id))
            (amount-calc (calculate-template-total template-id batch-size))
            (total-amount (get total amount-calc))
            (message-hash (sha256 (concat
                (concat (unwrap-panic (to-consensus-buff? template-id)) (unwrap-panic (to-consensus-buff? title)))
                (unwrap-panic (to-consensus-buff? nonce))
            )))
        )
        ;; Validations
        (asserts! (get active template) ERR_TEMPLATE_NOT_FOUND)
        (asserts! (get active signer) ERR_NOT_AUTHORIZED)
        (asserts! (is-eq nonce current-nonce) ERR_INVALID_NONCE)
        (asserts! (verify-passkey-signature signer-id message-hash signature) ERR_INVALID_SIGNATURE)
        (asserts! (<= total-amount (get-treasury-balance)) ERR_INSUFFICIENT_FUNDS)

        ;; Create proposal
        (map-set proposals proposal-id {
            title: title,
            description: (get description template),
            proposal-type: PROPOSAL_BATCH_TRANSFER,
            creator-signer-id: signer-id,
            target-contract: none,
            target-function: none,
            recipient: none,
            amount: total-amount,
            execution-data: none,
            created-at: current-time,
            expires-at: (+ current-time (* u7 u86400)),
            execution-time: none,
            approval-count: u1,
            status: STATUS_PENDING
        })

        ;; Copy template recipients to proposal
        (map-set batch-sizes proposal-id batch-size)
        (fold copy-template-to-proposal
            (generate-template-indices batch-size)
            { template-id: template-id, proposal-id: proposal-id })

        ;; Record creator's approval
        (map-set proposal-approvals { proposal-id: proposal-id, signer-id: signer-id } {
            approved-at: current-time,
            signature-hash: (sha256 signature)
        })

        ;; Update template usage
        (map-set proposal-templates template-id
            (merge template { times-used: (+ (get times-used template) u1) }))

        ;; Update signer stats
        (map-set signers signer-id (merge signer {
            last-activity: current-time,
            proposals-created: (+ (get proposals-created signer) u1),
            proposals-approved: (+ (get proposals-approved signer) u1)
        }))

        ;; Increment nonce
        (map-set signer-nonces signer-id (+ current-nonce u1))
        (var-set proposal-counter proposal-id)

        ;; Emit event
        (print {
            event: "proposal-from-template-created",
            proposal-id: proposal-id,
            template-id: template-id,
            signer-id: signer-id,
            batch-size: batch-size,
            total-amount: total-amount,
            timestamp: current-time
        })

        (ok proposal-id)))

;; Helper to calculate total amount from template
(define-private (calculate-template-total (template-id uint) (size uint))
    (fold sum-template-amount
          (generate-template-indices size)
          { template-id: template-id, total: u0 }))

;; Helper to sum template amounts
(define-private (sum-template-amount (index uint) (state { template-id: uint, total: uint }))
    (let ((amount (match (map-get? template-batch-recipients { template-id: (get template-id state), index: index })
                          recipient (get amount recipient)
                          u0)))
        { template-id: (get template-id state), total: (+ (get total state) amount) }))

;; Helper to generate template indices
(define-private (generate-template-indices (size uint))
    (if (<= size u0)
        (list)
        (if (<= size u5)
            (list u0 u1 u2 u3 u4)
            (if (<= size u10)
                (list u0 u1 u2 u3 u4 u5 u6 u7 u8 u9)
                (if (<= size u15)
                    (list u0 u1 u2 u3 u4 u5 u6 u7 u8 u9 u10 u11 u12 u13 u14)
                    (list u0 u1 u2 u3 u4 u5 u6 u7 u8 u9 u10 u11 u12 u13 u14 u15 u16 u17 u18 u19))))))

;; Helper to copy template recipient to proposal
(define-private (copy-template-to-proposal (index uint) (state { template-id: uint, proposal-id: uint }))
    (match (map-get? template-batch-recipients { template-id: (get template-id state), index: index })
        recipient
            (begin
                (map-set batch-recipients
                    { proposal-id: (get proposal-id state), index: index }
                    {
                        recipient: (get recipient recipient),
                        amount: (get amount recipient),
                        executed: false
                    })
                (var-set total-batch-recipients (+ (var-get total-batch-recipients) u1))
                state)
        state))

;; Deactivate template
(define-public (deactivate-template (template-id uint) (signer-id uint))
    (let
        (
            (template (unwrap! (map-get? proposal-templates template-id) ERR_TEMPLATE_NOT_FOUND))
            (signer (unwrap! (map-get? signers signer-id) ERR_SIGNER_NOT_FOUND))
        )
        ;; Only template creator or admin can deactivate
        (asserts! (or (is-eq signer-id (get created-by template))
                     (is-eq tx-sender CONTRACT_OWNER)) ERR_NOT_AUTHORIZED)

        (map-set proposal-templates template-id (merge template { active: false }))

        ;; Emit event
        (print {
            event: "template-deactivated",
            template-id: template-id,
            deactivated-by: signer-id,
            timestamp: stacks-block-time
        })

        (ok true)))

;; Proposal expiry extension (signer can extend expiry before it expires)
(define-constant ERR_CANNOT_EXTEND (err u17020))
(define-map proposal-extensions uint { extensions-used: uint, last-extended-at: uint })

(define-public (extend-proposal-expiry (proposal-id uint) (extension-days uint) (signer-id uint) (signature (buff 64)) (nonce uint))
    (let ((proposal (unwrap! (map-get? proposals proposal-id) ERR_PROPOSAL_NOT_FOUND))
          (signer (unwrap! (map-get? signers signer-id) ERR_SIGNER_NOT_FOUND))
          (current-nonce (get-signer-nonce signer-id))
          (current-time stacks-block-time)
          (extensions (default-to { extensions-used: u0, last-extended-at: u0 } (map-get? proposal-extensions proposal-id)))
          (new-expiry (+ (get expires-at proposal) (* extension-days u86400)))
          (message-hash (sha256 (concat (unwrap-panic (to-consensus-buff? proposal-id)) (unwrap-panic (to-consensus-buff? extension-days))))))
        (asserts! (is-eq (get status proposal) STATUS_PENDING) ERR_PROPOSAL_EXECUTED)
        (asserts! (< current-time (get expires-at proposal)) ERR_PROPOSAL_EXPIRED)
        (asserts! (< (get extensions-used extensions) u3) ERR_CANNOT_EXTEND)
        (asserts! (is-eq nonce current-nonce) ERR_INVALID_NONCE)
        (asserts! (verify-passkey-signature signer-id message-hash signature) ERR_INVALID_SIGNATURE)
        (map-set proposals proposal-id (merge proposal { expires-at: new-expiry }))
        (map-set proposal-extensions proposal-id { extensions-used: (+ (get extensions-used extensions) u1), last-extended-at: current-time })
        (map-set signer-nonces signer-id (+ current-nonce u1))
        (print { event: "proposal-expiry-extended", proposal-id: proposal-id, new-expiry: new-expiry, extended-by: signer-id, timestamp: current-time })
        (ok new-expiry)))

(define-read-only (get-proposal-extensions (proposal-id uint))
    (map-get? proposal-extensions proposal-id))
