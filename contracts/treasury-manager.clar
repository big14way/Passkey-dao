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
