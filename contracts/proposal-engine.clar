;; proposal-engine.clar
;; Advanced proposal types and execution engine
;; Uses Clarity 4 features: contract-hash?, stacks-block-time, to-ascii?

(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR_NOT_AUTHORIZED (err u17101))
(define-constant ERR_INVALID_CONTRACT (err u17102))
(define-constant ERR_PROPOSAL_NOT_FOUND (err u17103))

;; Execution status
(define-constant EXEC_SUCCESS u0)
(define-constant EXEC_FAILED u1)
(define-constant EXEC_PENDING u2)

(define-data-var execution-counter uint u0)

;; Verified execution targets
(define-map verified-targets
    principal
    {
        name: (string-ascii 64),
        contract-hash: (buff 32),
        verified-at: uint,
        execution-count: uint,
        active: bool
    }
)

;; Execution history
(define-map executions
    uint
    {
        proposal-id: uint,
        target-contract: principal,
        function-name: (string-ascii 64),
        executed-at: uint,
        executed-by: principal,
        status: uint,
        result-hash: (optional (buff 32))
    }
)

;; ========================================
;; Read-Only Functions
;; ========================================

(define-read-only (get-current-time) stacks-block-time)

(define-read-only (get-verified-target (target-contract principal))
    (map-get? verified-targets target-contract)
)

(define-read-only (get-execution (exec-id uint))
    (map-get? executions exec-id)
)

;; Verify target contract using contract-hash?
(define-read-only (is-target-verified (target-contract principal))
    (match (map-get? verified-targets target-contract)
        target (and
            (get active target)
            (match (contract-hash? target-contract)
                ok-hash (is-eq ok-hash (get contract-hash target))
                err-val false
            )
        )
        false
    )
)

;; Generate target info using to-ascii?
(define-read-only (generate-target-info (target-contract principal))
    (match (map-get? verified-targets target-contract)
        target (let
            (
                (exec-count-str (unwrap-panic (to-ascii? (get execution-count target))))
                (verified-str (unwrap-panic (to-ascii? (get verified-at target))))
            )
            (concat 
                (concat "Target: " (get name target))
                (concat (concat " | Executions: " exec-count-str) (concat " | Verified: " verified-str))
            )
        )
        "Target not found"
    )
)

;; Generate execution summary
(define-read-only (generate-execution-summary (exec-id uint))
    (match (map-get? executions exec-id)
        exec (let
            (
                (id-str (unwrap-panic (to-ascii? exec-id)))
                (proposal-str (unwrap-panic (to-ascii? (get proposal-id exec))))
                (status-str (unwrap-panic (to-ascii? (get status exec))))
            )
            (concat 
                (concat (concat "Execution #" id-str) (concat " | Proposal #" proposal-str))
                (concat " | Status: " status-str)
            )
        )
        "Execution not found"
    )
)

;; ========================================
;; Target Management
;; ========================================

;; Verify a contract as execution target
(define-public (verify-target (target-contract principal) (name (string-ascii 64)))
    (let
        (
            (contract-hash (unwrap! (contract-hash? target-contract) ERR_INVALID_CONTRACT))
            (current-time stacks-block-time)
        )
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
        
        (map-set verified-targets target-contract {
            name: name,
            contract-hash: contract-hash,
            verified-at: current-time,
            execution-count: u0,
            active: true
        })
        
        (print (generate-target-info target-contract))
        
        (ok true)
    )
)

;; Revoke target verification
(define-public (revoke-target (target-contract principal))
    (let
        (
            (target (unwrap! (map-get? verified-targets target-contract) ERR_INVALID_CONTRACT))
        )
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
        
        (map-set verified-targets target-contract (merge target { active: false }))
        
        (ok true)
    )
)

;; Re-verify target (check hash matches)
(define-public (reverify-target (target-contract principal))
    (let
        (
            (target (unwrap! (map-get? verified-targets target-contract) ERR_INVALID_CONTRACT))
        )
        (if (is-target-verified target-contract)
            (ok true)
            (begin
                (map-set verified-targets target-contract (merge target { active: false }))
                ERR_INVALID_CONTRACT
            )
        )
    )
)

;; ========================================
;; Execution Recording
;; ========================================

;; Record successful execution
(define-public (record-execution
    (proposal-id uint)
    (target-contract principal)
    (function-name (string-ascii 64))
    (result-hash (optional (buff 32))))
    (let
        (
            (exec-id (+ (var-get execution-counter) u1))
            (current-time stacks-block-time)
            (target (unwrap! (map-get? verified-targets target-contract) ERR_INVALID_CONTRACT))
        )
        ;; In production, would verify caller is treasury-manager
        
        (map-set executions exec-id {
            proposal-id: proposal-id,
            target-contract: target-contract,
            function-name: function-name,
            executed-at: current-time,
            executed-by: tx-sender,
            status: EXEC_SUCCESS,
            result-hash: result-hash
        })
        
        ;; Update target stats
        (map-set verified-targets target-contract (merge target {
            execution-count: (+ (get execution-count target) u1)
        }))
        
        (var-set execution-counter exec-id)
        
        (print (generate-execution-summary exec-id))
        
        (ok exec-id)
    )
)

;; Record failed execution
(define-public (record-failure
    (proposal-id uint)
    (target-contract principal)
    (function-name (string-ascii 64)))
    (let
        (
            (exec-id (+ (var-get execution-counter) u1))
            (current-time stacks-block-time)
        )
        (map-set executions exec-id {
            proposal-id: proposal-id,
            target-contract: target-contract,
            function-name: function-name,
            executed-at: current-time,
            executed-by: tx-sender,
            status: EXEC_FAILED,
            result-hash: none
        })
        
        (var-set execution-counter exec-id)
        
        (ok exec-id)
    )
)
