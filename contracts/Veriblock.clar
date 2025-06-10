;; title: Veriblock
;; version: 1.0.0
;; summary: KYC On-Demand Verifier - Share identity proofs without storing data
;; description: A privacy-focused KYC verification system that enables identity proof sharing without permanent data storage

(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR_UNAUTHORIZED (err u100))
(define-constant ERR_INVALID_VERIFIER (err u101))
(define-constant ERR_VERIFICATION_EXPIRED (err u102))
(define-constant ERR_ALREADY_VERIFIED (err u103))
(define-constant ERR_INVALID_PROOF (err u104))
(define-constant ERR_VERIFIER_NOT_FOUND (err u105))
(define-constant ERR_INSUFFICIENT_PAYMENT (err u106))
(define-constant ERR_VERIFICATION_NOT_FOUND (err u107))

(define-data-var verification-fee uint u1000000)
(define-data-var verifier-registration-fee uint u5000000)
(define-data-var verification-validity-period uint u144)

(define-map authorized-verifiers
  principal
  {
    name: (string-ascii 64),
    reputation-score: uint,
    total-verifications: uint,
    registration-block: uint,
    active: bool
  }
)

(define-map verification-requests
  { requester: principal, request-id: uint }
  {
    verifier: principal,
    proof-hash: (buff 32),
    verification-type: (string-ascii 32),
    created-at: uint,
    expires-at: uint,
    status: (string-ascii 16),
    fee-paid: uint
  }
)

(define-map user-verifications
  principal
  {
    last-verification-block: uint,
    verification-count: uint,
    current-verifier: (optional principal),
    verification-score: uint
  }
)

(define-map verification-proofs
  (buff 32)
  {
    requester: principal,
    verifier: principal,
    proof-type: (string-ascii 32),
    timestamp: uint,
    validity-period: uint
  }
)

(define-data-var next-request-id uint u1)

(define-public (register-verifier (name (string-ascii 64)))
  (let (
    (registration-fee (var-get verifier-registration-fee))
  )
    (asserts! (>= (stx-get-balance tx-sender) registration-fee) ERR_INSUFFICIENT_PAYMENT)
    (try! (stx-transfer? registration-fee tx-sender CONTRACT_OWNER))
    (map-set authorized-verifiers tx-sender {
      name: name,
      reputation-score: u100,
      total-verifications: u0,
      registration-block: stacks-block-height,
      active: true
    })
    (ok true)
  )
)

(define-public (deactivate-verifier (verifier principal))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (match (map-get? authorized-verifiers verifier)
      verifier-data (begin
        (map-set authorized-verifiers verifier (merge verifier-data { active: false }))
        (ok true)
      )
      ERR_VERIFIER_NOT_FOUND
    )
  )
)

(define-public (request-verification (verifier principal) (verification-type (string-ascii 32)) (proof-hash (buff 32)))
  (let (
    (request-id (var-get next-request-id))
    (fee (var-get verification-fee))
    (current-block stacks-block-height)
    (expiry-block (+ current-block (var-get verification-validity-period)))
  )
    (asserts! (>= (stx-get-balance tx-sender) fee) ERR_INSUFFICIENT_PAYMENT)
    (asserts! (is-verifier-active verifier) ERR_INVALID_VERIFIER)
    
    (try! (stx-transfer? fee tx-sender verifier))
    
    (map-set verification-requests 
      { requester: tx-sender, request-id: request-id }
      {
        verifier: verifier,
        proof-hash: proof-hash,
        verification-type: verification-type,
        created-at: current-block,
        expires-at: expiry-block,
        status: "pending",
        fee-paid: fee
      }
    )
    
    (var-set next-request-id (+ request-id u1))
    (ok request-id)
  )
)

(define-public (complete-verification (requester principal) (request-id uint) (verification-result bool))
  (let (
    (request-key { requester: requester, request-id: request-id })
  )
    (match (map-get? verification-requests request-key)
      request-data (begin
        (asserts! (is-eq tx-sender (get verifier request-data)) ERR_UNAUTHORIZED)
        (asserts! (< stacks-block-height (get expires-at request-data)) ERR_VERIFICATION_EXPIRED)
        (asserts! (is-eq (get status request-data) "pending") ERR_ALREADY_VERIFIED)
        
        (if verification-result
          (begin
            (map-set verification-requests request-key 
              (merge request-data { status: "verified" }))
            (map-set verification-proofs (get proof-hash request-data) {
              requester: requester,
              verifier: tx-sender,
              proof-type: (get verification-type request-data),
              timestamp: stacks-block-height,
              validity-period: (var-get verification-validity-period)
            })
            (update-user-verification requester tx-sender)
            (update-verifier-stats tx-sender)
          )
          (map-set verification-requests request-key 
            (merge request-data { status: "rejected" }))
        )
        (ok verification-result)
      )
      ERR_VERIFICATION_NOT_FOUND
    )
  )
)

(define-public (verify-proof (proof-hash (buff 32)))
  (match (map-get? verification-proofs proof-hash)
    proof-data (let (
      (expiry-block (+ (get timestamp proof-data) (get validity-period proof-data)))
    )
      (if (< stacks-block-height expiry-block)
        (ok {
          verifier: (get verifier proof-data),
          proof-type: (get proof-type proof-data),
          timestamp: (get timestamp proof-data),
          valid: true
        })
        (ok {
          verifier: (get verifier proof-data),
          proof-type: (get proof-type proof-data),
          timestamp: (get timestamp proof-data),
          valid: false
        })
      )
    )
    ERR_INVALID_PROOF
  )
)

(define-public (update-verification-fee (new-fee uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (var-set verification-fee new-fee)
    (ok true)
  )
)

(define-public (update-verifier-registration-fee (new-fee uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (var-set verifier-registration-fee new-fee)
    (ok true)
  )
)

(define-public (update-validity-period (new-period uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (var-set verification-validity-period new-period)
    (ok true)
  )
)

(define-private (is-verifier-active (verifier principal))
  (match (map-get? authorized-verifiers verifier)
    verifier-data (get active verifier-data)
    false
  )
)

(define-private (update-user-verification (user principal) (verifier principal))
  (let (
    (current-data (default-to 
      { last-verification-block: u0, verification-count: u0, current-verifier: none, verification-score: u0 }
      (map-get? user-verifications user)
    ))
  )
    (map-set user-verifications user {
      last-verification-block: stacks-block-height,
      verification-count: (+ (get verification-count current-data) u1),
      current-verifier: (some verifier),
      verification-score: (+ (get verification-score current-data) u10)
    })
  )
)

(define-private (update-verifier-stats (verifier principal))
  (match (map-get? authorized-verifiers verifier)
    verifier-data (begin
      (map-set authorized-verifiers verifier (merge verifier-data {
        total-verifications: (+ (get total-verifications verifier-data) u1),
        reputation-score: (+ (get reputation-score verifier-data) u1)
      }))
    )
    false
  )
)

(define-read-only (get-verifier-info (verifier principal))
  (map-get? authorized-verifiers verifier)
)

(define-read-only (get-verification-request (requester principal) (request-id uint))
  (map-get? verification-requests { requester: requester, request-id: request-id })
)

(define-read-only (get-user-verification-status (user principal))
  (map-get? user-verifications user)
)

(define-read-only (get-verification-fee)
  (var-get verification-fee)
)

(define-read-only (get-verifier-registration-fee)
  (var-get verifier-registration-fee)
)

(define-read-only (get-validity-period)
  (var-get verification-validity-period)
)

(define-read-only (is-proof-valid (proof-hash (buff 32)))
  (match (map-get? verification-proofs proof-hash)
    proof-data (< stacks-block-height (+ (get timestamp proof-data) (get validity-period proof-data)))
    false
  )
)

(define-read-only (get-contract-owner)
  CONTRACT_OWNER
)