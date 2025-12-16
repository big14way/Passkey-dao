;; signer-registry.clar
;; Registry for passkey signers with activity tracking
;; Uses Clarity 4 features: stacks-block-time, to-ascii?

(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR_NOT_AUTHORIZED (err u17201))
(define-constant ERR_SIGNER_NOT_FOUND (err u17202))
(define-constant ERR_SIGNER_EXISTS (err u17203))
(define-constant ERR_INACTIVE_SIGNER (err u17204))

;; Inactivity threshold: 90 days
(define-constant INACTIVITY_THRESHOLD u7776000)

(define-data-var signer-counter uint u0)
(define-data-var active-signers uint u0)

;; Signer registry (mirrors treasury-manager but for additional tracking)
(define-map signer-profiles
    uint
    {
        pubkey-hash: (buff 32),
        alias: (string-ascii 32),
        email-hash: (optional (buff 32)),
        registered-at: uint,
        last-active: uint,
        total-approvals: uint,
        total-proposals: uint,
        reputation-score: uint,
        active: bool
    }
)

;; Activity log
(define-map activity-log
    { signer-id: uint, activity-index: uint }
    {
        activity-type: (string-ascii 32),
        timestamp: uint,
        proposal-id: (optional uint),
        details: (optional (string-ascii 128))
    }
)

;; Activity count per signer
(define-map signer-activity-count
    uint
    uint
)

;; ========================================
;; Read-Only Functions
;; ========================================

(define-read-only (get-current-time) stacks-block-time)

(define-read-only (get-signer-profile (signer-id uint))
    (map-get? signer-profiles signer-id)
)

(define-read-only (get-activity (signer-id uint) (activity-index uint))
    (map-get? activity-log { signer-id: signer-id, activity-index: activity-index })
)

(define-read-only (get-activity-count (signer-id uint))
    (default-to u0 (map-get? signer-activity-count signer-id))
)

;; Check if signer is inactive
(define-read-only (is-signer-inactive (signer-id uint))
    (match (map-get? signer-profiles signer-id)
        profile (> (- stacks-block-time (get last-active profile)) INACTIVITY_THRESHOLD)
        true
    )
)

;; Calculate signer reputation
(define-read-only (calculate-reputation (signer-id uint))
    (match (map-get? signer-profiles signer-id)
        profile (let
            (
                (approvals (get total-approvals profile))
                (proposals (get total-proposals profile))
                (base-score (* (+ approvals (* proposals u2)) u100))
                (inactive-penalty (if (is-signer-inactive signer-id) u50 u0))
            )
            (if (> base-score inactive-penalty)
                (- base-score inactive-penalty)
                u0
            )
        )
        u0
    )
)

;; Generate signer info using to-ascii?
(define-read-only (generate-signer-info (signer-id uint))
    (match (map-get? signer-profiles signer-id)
        profile (let
            (
                (id-str (unwrap-panic (to-ascii? signer-id)))
                (approvals-str (unwrap-panic (to-ascii? (get total-approvals profile))))
                (proposals-str (unwrap-panic (to-ascii? (get total-proposals profile))))
                (reputation (calculate-reputation signer-id))
                (rep-str (unwrap-panic (to-ascii? reputation)))
            )
            (concat 
                (concat (concat "Signer #" id-str) (concat ": " (get alias profile)))
                (concat (concat " | Approvals: " approvals-str)
                    (concat (concat " | Proposals: " proposals-str)
                        (concat " | Reputation: " rep-str)
                    )
                )
            )
        )
        "Signer not found"
    )
)

;; Get time since last activity
(define-read-only (get-time-since-active (signer-id uint))
    (match (map-get? signer-profiles signer-id)
        profile (let
            (
                (inactive-time (- stacks-block-time (get last-active profile)))
                (days (/ inactive-time u86400))
                (days-str (unwrap-panic (to-ascii? days)))
            )
            (concat days-str " days since last activity")
        )
        "Signer not found"
    )
)

;; Get registry stats
(define-read-only (get-registry-stats)
    {
        total-signers: (var-get signer-counter),
        active-signers: (var-get active-signers),
        current-time: stacks-block-time
    }
)

;; ========================================
;; Signer Management
;; ========================================

;; Register signer profile
(define-public (register-signer
    (pubkey-hash (buff 32))
    (alias (string-ascii 32))
    (email-hash (optional (buff 32))))
    (let
        (
            (signer-id (+ (var-get signer-counter) u1))
            (current-time stacks-block-time)
        )
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
        
        (map-set signer-profiles signer-id {
            pubkey-hash: pubkey-hash,
            alias: alias,
            email-hash: email-hash,
            registered-at: current-time,
            last-active: current-time,
            total-approvals: u0,
            total-proposals: u0,
            reputation-score: u100,
            active: true
        })
        
        (var-set signer-counter signer-id)
        (var-set active-signers (+ (var-get active-signers) u1))
        
        (print (generate-signer-info signer-id))
        
        (ok signer-id)
    )
)

;; Update signer alias
(define-public (update-alias (signer-id uint) (new-alias (string-ascii 32)))
    (let
        (
            (profile (unwrap! (map-get? signer-profiles signer-id) ERR_SIGNER_NOT_FOUND))
        )
        ;; In production, would verify caller is the signer
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
        
        (map-set signer-profiles signer-id (merge profile {
            alias: new-alias,
            last-active: stacks-block-time
        }))
        
        (ok true)
    )
)

;; Record activity
(define-public (record-activity
    (signer-id uint)
    (activity-type (string-ascii 32))
    (proposal-id (optional uint))
    (details (optional (string-ascii 128))))
    (let
        (
            (profile (unwrap! (map-get? signer-profiles signer-id) ERR_SIGNER_NOT_FOUND))
            (activity-index (get-activity-count signer-id))
            (current-time stacks-block-time)
        )
        ;; Record activity
        (map-set activity-log { signer-id: signer-id, activity-index: activity-index } {
            activity-type: activity-type,
            timestamp: current-time,
            proposal-id: proposal-id,
            details: details
        })
        
        ;; Update count
        (map-set signer-activity-count signer-id (+ activity-index u1))
        
        ;; Update profile
        (map-set signer-profiles signer-id (merge profile {
            last-active: current-time,
            total-approvals: (if (is-eq activity-type "approval")
                (+ (get total-approvals profile) u1)
                (get total-approvals profile)
            ),
            total-proposals: (if (is-eq activity-type "proposal")
                (+ (get total-proposals profile) u1)
                (get total-proposals profile)
            )
        }))
        
        (ok activity-index)
    )
)

;; Deactivate inactive signer
(define-public (deactivate-inactive (signer-id uint))
    (let
        (
            (profile (unwrap! (map-get? signer-profiles signer-id) ERR_SIGNER_NOT_FOUND))
        )
        (asserts! (is-signer-inactive signer-id) ERR_NOT_AUTHORIZED)
        
        (map-set signer-profiles signer-id (merge profile { active: false }))
        (var-set active-signers (- (var-get active-signers) u1))
        
        (ok true)
    )
)

;; Reactivate signer
(define-public (reactivate-signer (signer-id uint))
    (let
        (
            (profile (unwrap! (map-get? signer-profiles signer-id) ERR_SIGNER_NOT_FOUND))
        )
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
        (asserts! (not (get active profile)) ERR_SIGNER_EXISTS)
        
        (map-set signer-profiles signer-id (merge profile {
            active: true,
            last-active: stacks-block-time
        }))
        (var-set active-signers (+ (var-get active-signers) u1))
        
        (ok true)
    )
)
