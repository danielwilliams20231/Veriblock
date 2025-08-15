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
(define-constant ERR_INSUFFICIENT_STAKE (err u108))
(define-constant ERR_STAKE_LOCKED (err u109))
(define-constant ERR_INVALID_AMOUNT (err u110))
(define-constant ERR_NO_STAKE (err u111))
(define-constant ERR_SLASHING_FAILED (err u112))
(define-constant ERR_BIDDING_CLOSED (err u113))
(define-constant ERR_INVALID_BID (err u114))
(define-constant ERR_BID_NOT_FOUND (err u115))
(define-constant ERR_CONSENSUS_NOT_REACHED (err u116))
(define-constant ERR_ALREADY_VOTED (err u117))
(define-constant ERR_CONSENSUS_EXPIRED (err u118))
(define-constant ERR_INVALID_THRESHOLD (err u119))
(define-constant ERR_INSUFFICIENT_VERIFIERS (err u120))
(define-constant ERR_CONSENSUS_CLOSED (err u121))

(define-data-var verification-fee uint u1000000)
(define-data-var verifier-registration-fee uint u5000000)
(define-data-var verification-validity-period uint u144)
(define-data-var minimum-stake-amount uint u10000000)
(define-data-var slashing-percentage uint u10)
(define-data-var staking-reward-rate uint u5)
(define-data-var bidding-period uint u144)
(define-data-var consensus-threshold-percentage uint u67)
(define-data-var consensus-expiry-period uint u288)
(define-data-var minimum-consensus-verifiers uint u3)

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

(define-map verifier-stakes
  principal
  {
    staked-amount: uint,
    stake-timestamp: uint,
    lock-period: uint,
    rewards-earned: uint,
    slashed-amount: uint
  }
)

(define-map verification-bids
  { requester: principal, request-id: uint }
  {
    bid-amount: uint,
    stake-requirement: uint,
    bid-deadline: uint,
    selected-verifier: (optional principal),
    bid-status: (string-ascii 16)
  }
)

(define-map verifier-bid-responses
  { requester: principal, request-id: uint, verifier: principal }
  {
    bid-amount: uint,
    stake-pledged: uint,
    reputation-bonus: uint,
    bid-timestamp: uint
  }
)

(define-map stake-lockups
  { verifier: principal, lockup-id: uint }
  {
    amount: uint,
    locked-until: uint,
    lock-type: (string-ascii 16)
  }
)

;; Multi-party verification consensus system
(define-map consensus-verifications
  uint
  {
    requester: principal,
    proof-hash: (buff 32),
    verification-type: (string-ascii 32),
    required-verifiers: uint,
    threshold-percentage: uint,
    total-fee: uint,
    fee-per-verifier: uint,
    created-at: uint,
    expires-at: uint,
    status: (string-ascii 16),
    votes-for: uint,
    votes-against: uint,
    total-votes: uint,
    consensus-reached: bool
  }
)

(define-map consensus-votes
  { consensus-id: uint, verifier: principal }
  {
    vote: bool,
    weight: uint,
    timestamp: uint,
    reasoning: (string-ascii 128)
  }
)

(define-map consensus-participants
  { consensus-id: uint, verifier: principal }
  {
    invited: bool,
    responded: bool,
    fee-claimed: bool
  }
)

(define-data-var next-request-id uint u1)
(define-data-var next-lockup-id uint u1)
(define-data-var next-consensus-id uint u1)

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

(define-public (stake-tokens (amount uint) (lock-period uint))
  (let (
    (minimum-stake (var-get minimum-stake-amount))
    (current-stake (default-to 
      { staked-amount: u0, stake-timestamp: u0, lock-period: u0, rewards-earned: u0, slashed-amount: u0 }
      (map-get? verifier-stakes tx-sender)
    ))
    (lockup-id (var-get next-lockup-id))
  )
    (asserts! (>= amount minimum-stake) ERR_INSUFFICIENT_STAKE)
    (asserts! (>= (stx-get-balance tx-sender) amount) ERR_INSUFFICIENT_PAYMENT)
    (asserts! (is-verifier-active tx-sender) ERR_INVALID_VERIFIER)
    (asserts! (> lock-period u0) ERR_INVALID_AMOUNT)
    
    (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
    
    (map-set verifier-stakes tx-sender {
      staked-amount: (+ (get staked-amount current-stake) amount),
      stake-timestamp: stacks-block-height,
      lock-period: lock-period,
      rewards-earned: (get rewards-earned current-stake),
      slashed-amount: (get slashed-amount current-stake)
    })
    
    (map-set stake-lockups 
      { verifier: tx-sender, lockup-id: lockup-id }
      {
        amount: amount,
        locked-until: (+ stacks-block-height lock-period),
        lock-type: "verification"
      }
    )
    
    (var-set next-lockup-id (+ lockup-id u1))
    (ok lockup-id)
  )
)

(define-public (unstake-tokens (lockup-id uint))
  (let (
    (lockup-key { verifier: tx-sender, lockup-id: lockup-id })
    (current-stake (unwrap! (map-get? verifier-stakes tx-sender) ERR_NO_STAKE))
  )
    (match (map-get? stake-lockups lockup-key)
      lockup-data (begin
        (asserts! (>= stacks-block-height (get locked-until lockup-data)) ERR_STAKE_LOCKED)
        (asserts! (is-eq (get lock-type lockup-data) "verification") ERR_INVALID_AMOUNT)
        
        (let (
          (unlock-amount (get amount lockup-data))
          (new-staked-amount (- (get staked-amount current-stake) unlock-amount))
        )
          (try! (as-contract (stx-transfer? unlock-amount tx-sender tx-sender)))
          
          (map-set verifier-stakes tx-sender 
            (merge current-stake { staked-amount: new-staked-amount }))
          
          (map-delete stake-lockups lockup-key)
          (ok unlock-amount)
        )
      )
      ERR_BID_NOT_FOUND
    )
  )
)

(define-public (create-verification-bid (verification-type (string-ascii 32)) (stake-requirement uint) (max-fee uint))
  (let (
    (request-id (var-get next-request-id))
    (bid-deadline (+ stacks-block-height (var-get bidding-period)))
  )
    (asserts! (> stake-requirement u0) ERR_INVALID_AMOUNT)
    (asserts! (> max-fee u0) ERR_INVALID_AMOUNT)
    (asserts! (>= (stx-get-balance tx-sender) max-fee) ERR_INSUFFICIENT_PAYMENT)
    
    (map-set verification-bids 
      { requester: tx-sender, request-id: request-id }
      {
        bid-amount: max-fee,
        stake-requirement: stake-requirement,
        bid-deadline: bid-deadline,
        selected-verifier: none,
        bid-status: "open"
      }
    )
    
    (var-set next-request-id (+ request-id u1))
    (ok request-id)
  )
)

(define-public (submit-verification-bid (requester principal) (request-id uint) (bid-amount uint))
  (let (
    (bid-key { requester: requester, request-id: request-id })
    (response-key { requester: requester, request-id: request-id, verifier: tx-sender })
    (current-stake (unwrap! (map-get? verifier-stakes tx-sender) ERR_NO_STAKE))
    (verifier-info (unwrap! (map-get? authorized-verifiers tx-sender) ERR_INVALID_VERIFIER))
  )
    (match (map-get? verification-bids bid-key)
      bid-data (begin
        (asserts! (is-eq (get bid-status bid-data) "open") ERR_BIDDING_CLOSED)
        (asserts! (< stacks-block-height (get bid-deadline bid-data)) ERR_BIDDING_CLOSED)
        (asserts! (>= (get staked-amount current-stake) (get stake-requirement bid-data)) ERR_INSUFFICIENT_STAKE)
        (asserts! (<= bid-amount (get bid-amount bid-data)) ERR_INVALID_BID)
        (asserts! (is-verifier-active tx-sender) ERR_INVALID_VERIFIER)
        
        (let (
          (reputation-bonus (/ (get reputation-score verifier-info) u10))
          (stake-pledged (get stake-requirement bid-data))
        )
          (map-set verifier-bid-responses response-key {
            bid-amount: bid-amount,
            stake-pledged: stake-pledged,
            reputation-bonus: reputation-bonus,
            bid-timestamp: stacks-block-height
          })
          
          (ok true)
        )
      )
      ERR_VERIFICATION_NOT_FOUND
    )
  )
)

(define-public (accept-verification-bid (request-id uint) (verifier principal))
  (let (
    (bid-key { requester: tx-sender, request-id: request-id })
    (response-key { requester: tx-sender, request-id: request-id, verifier: verifier })
  )
    (match (map-get? verification-bids bid-key)
      bid-data (begin
        (asserts! (is-eq (get bid-status bid-data) "open") ERR_BIDDING_CLOSED)
        (asserts! (< stacks-block-height (get bid-deadline bid-data)) ERR_BIDDING_CLOSED)
        
        (match (map-get? verifier-bid-responses response-key)
          response-data (begin
            (try! (stx-transfer? (get bid-amount response-data) tx-sender verifier))
            
            (map-set verification-bids bid-key 
              (merge bid-data { 
                selected-verifier: (some verifier),
                bid-status: "accepted"
              }))
            
            (ok true)
          )
          ERR_BID_NOT_FOUND
        )
      )
      ERR_VERIFICATION_NOT_FOUND
    )
  )
)

(define-public (slash-verifier-stake (verifier principal) (slash-amount uint))
  (let (
    (current-stake (unwrap! (map-get? verifier-stakes verifier) ERR_NO_STAKE))
    (max-slash (/ (* (get staked-amount current-stake) (var-get slashing-percentage)) u100))
  )
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (asserts! (<= slash-amount max-slash) ERR_INVALID_AMOUNT)
    (asserts! (> slash-amount u0) ERR_INVALID_AMOUNT)
    
    (map-set verifier-stakes verifier 
      (merge current-stake { 
        slashed-amount: (+ (get slashed-amount current-stake) slash-amount),
        staked-amount: (- (get staked-amount current-stake) slash-amount)
      }))
    
    (ok slash-amount)
  )
)

(define-public (calculate-staking-rewards (verifier principal))
  (let (
    (current-stake (unwrap! (map-get? verifier-stakes verifier) ERR_NO_STAKE))
    (blocks-staked (- stacks-block-height (get stake-timestamp current-stake)))
    (reward-rate (var-get staking-reward-rate))
  )
    (asserts! (is-eq tx-sender verifier) ERR_UNAUTHORIZED)
    
    (let (
      (base-reward (/ (* (get staked-amount current-stake) reward-rate blocks-staked) u100000))
      (total-rewards (+ (get rewards-earned current-stake) base-reward))
    )
      (map-set verifier-stakes verifier 
        (merge current-stake { 
          rewards-earned: total-rewards,
          stake-timestamp: stacks-block-height
        }))
      
      (ok total-rewards)
    )
  )
)

(define-public (withdraw-staking-rewards)
  (let (
    (current-stake (unwrap! (map-get? verifier-stakes tx-sender) ERR_NO_STAKE))
    (withdrawable-rewards (get rewards-earned current-stake))
  )
    (asserts! (> withdrawable-rewards u0) ERR_INVALID_AMOUNT)
    
    (try! (as-contract (stx-transfer? withdrawable-rewards tx-sender tx-sender)))
    
    (map-set verifier-stakes tx-sender 
      (merge current-stake { rewards-earned: u0 }))
    
    (ok withdrawable-rewards)
  )
)

(define-public (update-minimum-stake (new-amount uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (asserts! (> new-amount u0) ERR_INVALID_AMOUNT)
    (var-set minimum-stake-amount new-amount)
    (ok true)
  )
)

(define-public (update-slashing-percentage (new-percentage uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (asserts! (<= new-percentage u50) ERR_INVALID_AMOUNT)
    (var-set slashing-percentage new-percentage)
    (ok true)
  )
)

(define-public (update-staking-reward-rate (new-rate uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (asserts! (<= new-rate u20) ERR_INVALID_AMOUNT)
    (var-set staking-reward-rate new-rate)
    (ok true)
  )
)

(define-public (update-bidding-period (new-period uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (asserts! (> new-period u0) ERR_INVALID_AMOUNT)
    (var-set bidding-period new-period)
    (ok true)
  )
)

(define-read-only (get-verifier-stake (verifier principal))
  (map-get? verifier-stakes verifier)
)

(define-read-only (get-verification-bid (requester principal) (request-id uint))
  (map-get? verification-bids { requester: requester, request-id: request-id })
)

(define-read-only (get-bid-response (requester principal) (request-id uint) (verifier principal))
  (map-get? verifier-bid-responses { requester: requester, request-id: request-id, verifier: verifier })
)

(define-read-only (get-stake-lockup (verifier principal) (lockup-id uint))
  (map-get? stake-lockups { verifier: verifier, lockup-id: lockup-id })
)

(define-read-only (get-minimum-stake-amount)
  (var-get minimum-stake-amount)
)

(define-read-only (get-slashing-percentage)
  (var-get slashing-percentage)
)

(define-read-only (get-staking-reward-rate)
  (var-get staking-reward-rate)
)

(define-read-only (get-bidding-period)
  (var-get bidding-period)
)

(define-read-only (calculate-verifier-score (verifier principal))
  (let (
    (verifier-info (unwrap! (map-get? authorized-verifiers verifier) (err "not-found")))
    (stake-info (map-get? verifier-stakes verifier))
  )
    (match stake-info
      stake-data (let (
        (base-reputation (get reputation-score verifier-info))
        (stake-bonus (/ (get staked-amount stake-data) u1000000))
        (verification-bonus (* (get total-verifications verifier-info) u2))
      )
        (ok (+ base-reputation stake-bonus verification-bonus))
      )
      (ok (get reputation-score verifier-info))
    )
  )
)

;; Multi-party verification consensus functions
(define-public (create-consensus-verification 
  (verification-type (string-ascii 32)) 
  (proof-hash (buff 32)) 
  (required-verifiers uint) 
  (verifier-list (list 10 principal))
  (total-fee uint))
  (let (
    (consensus-id (var-get next-consensus-id))
    (fee-per-verifier (/ total-fee required-verifiers))
  )
    ;; Validation checks
    (asserts! (>= required-verifiers (var-get minimum-consensus-verifiers)) ERR_INSUFFICIENT_VERIFIERS)
    (asserts! (<= required-verifiers (len verifier-list)) ERR_INSUFFICIENT_VERIFIERS)
    (asserts! (> total-fee u0) ERR_INVALID_AMOUNT)
    (asserts! (>= (stx-get-balance tx-sender) total-fee) ERR_INSUFFICIENT_PAYMENT)
    
    ;; Transfer fee and create verification, then complete setup
    (match (stx-transfer? total-fee tx-sender (as-contract tx-sender))
      success (if (map-set consensus-verifications consensus-id {
                    requester: tx-sender,
                    proof-hash: proof-hash,
                    verification-type: verification-type,
                    required-verifiers: required-verifiers,
                    threshold-percentage: (var-get consensus-threshold-percentage),
                    total-fee: total-fee,
                    fee-per-verifier: fee-per-verifier,
                    created-at: stacks-block-height,
                    expires-at: (+ stacks-block-height (var-get consensus-expiry-period)),
                    status: "pending",
                    votes-for: u0,
                    votes-against: u0,
                    total-votes: u0,
                    consensus-reached: false
                  })
                ;; Complete setup and return consensus ID
                (let (
                  (invite-result (invite-verifiers-to-consensus consensus-id verifier-list))
                )
                  (var-set next-consensus-id (+ consensus-id u1))
                  (ok consensus-id)
                )
                ;; Return error if map-set fails
                ERR_INVALID_AMOUNT
              )
      error ERR_INSUFFICIENT_PAYMENT
    )
  )
)

(define-public (cast-consensus-vote 
  (consensus-id uint) 
  (vote bool) 
  (reasoning (string-ascii 128)))
  (let (
    (vote-key { consensus-id: consensus-id, verifier: tx-sender })
    (participant-key { consensus-id: consensus-id, verifier: tx-sender })
    (verifier-info (unwrap! (map-get? authorized-verifiers tx-sender) ERR_INVALID_VERIFIER))
  )
    (match (map-get? consensus-verifications consensus-id)
      consensus-data (begin
        ;; Validation checks
        (asserts! (is-eq (get status consensus-data) "pending") ERR_CONSENSUS_CLOSED)
        (asserts! (< stacks-block-height (get expires-at consensus-data)) ERR_CONSENSUS_EXPIRED)
        (asserts! (is-none (map-get? consensus-votes vote-key)) ERR_ALREADY_VOTED)
        (asserts! (is-verifier-active tx-sender) ERR_INVALID_VERIFIER)
        
        ;; Check if verifier is invited
        (match (map-get? consensus-participants participant-key)
          participant-data (begin
            (asserts! (get invited participant-data) ERR_UNAUTHORIZED)
            
            ;; Calculate vote weight based on reputation and stake
            (let (
              (base-weight u1)
              (reputation-weight (/ (get reputation-score verifier-info) u50))
              (stake-weight (match (map-get? verifier-stakes tx-sender)
                stake-data (/ (get staked-amount stake-data) u5000000)
                u0
              ))
              (total-weight (+ base-weight reputation-weight stake-weight))
            )
              ;; Record the vote
              (map-set consensus-votes vote-key {
                vote: vote,
                weight: total-weight,
                timestamp: stacks-block-height,
                reasoning: reasoning
              })
              
              ;; Update participant status
              (map-set consensus-participants participant-key 
                (merge participant-data { responded: true }))
              
              ;; Update consensus vote counts
              (let (
                (new-votes-for (if vote 
                  (+ (get votes-for consensus-data) total-weight) 
                  (get votes-for consensus-data)))
                (new-votes-against (if vote 
                  (get votes-against consensus-data)
                  (+ (get votes-against consensus-data) total-weight)))
                (new-total-votes (+ (get total-votes consensus-data) total-weight))
              )
                (map-set consensus-verifications consensus-id 
                  (merge consensus-data {
                    votes-for: new-votes-for,
                    votes-against: new-votes-against,
                    total-votes: new-total-votes
                  }))
                
                ;; Check if consensus threshold is reached
                (unwrap-panic (check-consensus-threshold consensus-id))
                (ok total-weight)
              )
            )
          )
          ERR_UNAUTHORIZED
        )
      )
      ERR_VERIFICATION_NOT_FOUND
    )
  )
)

(define-public (finalize-consensus (consensus-id uint))
  (match (map-get? consensus-verifications consensus-id)
    consensus-data (begin
      ;; Only requester or contract owner can finalize
      (asserts! (or (is-eq tx-sender (get requester consensus-data)) 
                    (is-eq tx-sender CONTRACT_OWNER)) ERR_UNAUTHORIZED)
      (asserts! (or (get consensus-reached consensus-data)
                    (>= stacks-block-height (get expires-at consensus-data))) ERR_CONSENSUS_NOT_REACHED)
      
      (let (
        (votes-for (get votes-for consensus-data))
        (votes-against (get votes-against consensus-data))
        (total-votes (get total-votes consensus-data))
        (threshold-percentage (get threshold-percentage consensus-data))
        (verification-passed (>= (* votes-for u100) (* total-votes threshold-percentage)))
      )
        ;; Update final status
        (map-set consensus-verifications consensus-id 
          (merge consensus-data { 
            status: (if verification-passed "verified" "rejected"),
            consensus-reached: true
          }))
        
        ;; If verification passed, create proof record
        (if verification-passed
          (begin
            (map-set verification-proofs (get proof-hash consensus-data) {
              requester: (get requester consensus-data),
              verifier: CONTRACT_OWNER, ;; Multi-party verification by contract
              proof-type: (get verification-type consensus-data),
              timestamp: stacks-block-height,
              validity-period: (var-get verification-validity-period)
            })
            ;; Distribute fees to participating verifiers
            (unwrap-panic (distribute-consensus-fees consensus-id))
          )
          ;; Refund requester if verification failed
          (try! (as-contract (stx-transfer? (get total-fee consensus-data) 
                                           tx-sender 
                                           (get requester consensus-data))))
        )
        
        (ok verification-passed)
      )
    )
    ERR_VERIFICATION_NOT_FOUND
  )
)

(define-public (claim-consensus-fee (consensus-id uint))
  (let (
    (participant-key { consensus-id: consensus-id, verifier: tx-sender })
    (vote-key { consensus-id: consensus-id, verifier: tx-sender })
  )
    (match (map-get? consensus-verifications consensus-id)
      consensus-data (begin
        (asserts! (is-eq (get status consensus-data) "verified") ERR_CONSENSUS_NOT_REACHED)
        
        (match (map-get? consensus-participants participant-key)
          participant-data (begin
            (asserts! (get responded participant-data) ERR_UNAUTHORIZED)
            (asserts! (not (get fee-claimed participant-data)) ERR_ALREADY_VERIFIED)
            
            ;; Check if verifier voted correctly (for verification)
            (match (map-get? consensus-votes vote-key)
              vote-data (begin
                (asserts! (get vote vote-data) ERR_UNAUTHORIZED) ;; Must have voted "yes"
                
                (let (
                  (fee-amount (get fee-per-verifier consensus-data))
                )
                  ;; Mark fee as claimed
                  (map-set consensus-participants participant-key 
                    (merge participant-data { fee-claimed: true }))
                  
                  ;; Transfer fee to verifier
                  (unwrap! (as-contract (stx-transfer? fee-amount tx-sender tx-sender)) ERR_INSUFFICIENT_PAYMENT)
                  (ok fee-amount)
                )
              )
              ERR_VERIFICATION_NOT_FOUND
            )
          )
          ERR_UNAUTHORIZED
        )
      )
      ERR_VERIFICATION_NOT_FOUND
    )
  )
)

;; Private helper functions for consensus system
(define-private (invite-verifiers-to-consensus (consensus-id uint) (verifier-list (list 10 principal)))
  (begin
    (map invite-single-verifier 
         (map make-participant-tuple 
              (map make-consensus-tuple 
                   verifier-list 
                   (list consensus-id consensus-id consensus-id consensus-id consensus-id 
                         consensus-id consensus-id consensus-id consensus-id consensus-id))))
    (ok true)
  )
)

(define-private (make-consensus-tuple (verifier principal) (consensus-id uint))
  { verifier: verifier, consensus-id: consensus-id }
)

(define-private (make-participant-tuple (data { verifier: principal, consensus-id: uint }))
  { 
    key: { consensus-id: (get consensus-id data), verifier: (get verifier data) },
    verifier: (get verifier data)
  }
)

(define-private (invite-single-verifier (data { key: { consensus-id: uint, verifier: principal }, verifier: principal }))
  (if (is-verifier-active (get verifier data))
    (map-set consensus-participants (get key data) {
      invited: true,
      responded: false,
      fee-claimed: false
    })
    false
  )
)

(define-private (check-consensus-threshold (consensus-id uint))
  (match (map-get? consensus-verifications consensus-id)
    consensus-data (let (
      (votes-for (get votes-for consensus-data))
      (total-votes (get total-votes consensus-data))
      (required-verifiers (get required-verifiers consensus-data))
      (threshold-percentage (get threshold-percentage consensus-data))
      (min-votes-needed (/ (* required-verifiers u2) u3)) ;; At least 2/3 of required verifiers
    )
      (if (and (>= total-votes min-votes-needed)
               (>= (* votes-for u100) (* total-votes threshold-percentage)))
        (begin
          (map-set consensus-verifications consensus-id 
            (merge consensus-data { consensus-reached: true }))
          (ok true)
        )
        (ok false)
      )
    )
    ERR_VERIFICATION_NOT_FOUND
  )
)

(define-private (distribute-consensus-fees (consensus-id uint))
  (ok true) ;; Fees are claimed individually by verifiers
)

;; Configuration functions for consensus system
(define-public (update-consensus-threshold (new-threshold uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (asserts! (and (> new-threshold u50) (<= new-threshold u100)) ERR_INVALID_THRESHOLD)
    (var-set consensus-threshold-percentage new-threshold)
    (ok true)
  )
)

(define-public (update-consensus-expiry-period (new-period uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (asserts! (> new-period u0) ERR_INVALID_AMOUNT)
    (var-set consensus-expiry-period new-period)
    (ok true)
  )
)

(define-public (update-minimum-consensus-verifiers (new-minimum uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (asserts! (and (>= new-minimum u2) (<= new-minimum u10)) ERR_INVALID_AMOUNT)
    (var-set minimum-consensus-verifiers new-minimum)
    (ok true)
  )
)

;; Read-only functions for consensus system
(define-read-only (get-consensus-verification (consensus-id uint))
  (map-get? consensus-verifications consensus-id)
)

(define-read-only (get-consensus-vote (consensus-id uint) (verifier principal))
  (map-get? consensus-votes { consensus-id: consensus-id, verifier: verifier })
)

(define-read-only (get-consensus-participant (consensus-id uint) (verifier principal))
  (map-get? consensus-participants { consensus-id: consensus-id, verifier: verifier })
)

(define-read-only (get-consensus-threshold-percentage)
  (var-get consensus-threshold-percentage)
)

(define-read-only (get-consensus-expiry-period)
  (var-get consensus-expiry-period)
)

(define-read-only (get-minimum-consensus-verifiers)
  (var-get minimum-consensus-verifiers)
)



