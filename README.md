# 🔐 Veriblock - KYC On-Demand Verifier

> 🛡️ Share identity proofs without storing data - Privacy-focused KYC verification on Stacks blockchain

## 📋 Overview

Veriblock is a decentralized KYC (Know Your Customer) verification system that enables users to prove their identity without permanently storing sensitive personal data on the blockchain. The system uses cryptographic proof hashes and time-limited verifications to maintain privacy while ensuring compliance.

## ✨ Key Features

- 🔒 **Privacy-First**: No personal data stored on-chain
- ⏰ **Time-Limited Proofs**: Verifications expire automatically
- 👥 **Decentralized Verifiers**: Multiple authorized verification providers
- 💰 **Fee-Based System**: Economic incentives for verifiers
- 🎯 **On-Demand Verification**: Request verification only when needed
- 📊 **Reputation System**: Track verifier performance and reliability

## 🚀 Getting Started

### Prerequisites

- Clarinet CLI installed
- Stacks wallet with STX tokens
- Basic understanding of Clarity smart contracts

### Installation

```bash
git clone <your-repo>
cd veriblock
clarinet check
```

## 📖 Usage Guide

### For Verifiers 👨‍💼

#### 1. Register as a Verifier
```clarity
(contract-call? .Veriblock register-verifier "Your Verification Service Name")
```

#### 2. Complete Verification Requests
```clarity
(contract-call? .Veriblock complete-verification 'SP1234... u1 true)
```

### For Users 🙋‍♀️

#### 1. Request Verification
```clarity
(contract-call? .Veriblock request-verification 'SP-VERIFIER... "identity" 0x1234...)
```

#### 2. Share Your Proof
```clarity
(contract-call? .Veriblock verify-proof 0x1234...)
```

### For Service Providers 🏢

#### Verify User Proofs
```clarity
(contract-call? .Veriblock is-proof-valid 0x1234...)
```

## 🔧 Contract Functions

### Public Functions

| Function | Description | Parameters |
|----------|-------------|------------|
| `register-verifier` | Register as authorized verifier | `name: string` |
| `request-verification` | Request identity verification | `verifier: principal, type: string, proof-hash: buff` |
| `complete-verification` | Complete verification process | `requester: principal, request-id: uint, result: bool` |
| `verify-proof` | Verify a proof hash | `proof-hash: buff` |

### Read-Only Functions

| Function | Description | Returns |
|----------|-------------|---------|
| `get-verifier-info` | Get verifier details | Verifier info object |
| `get-user-verification-status` | Get user's verification status | User verification data |
| `is-proof-valid` | Check if proof is still valid | Boolean |
| `get-verification-fee` | Current verification fee | Fee amount in µSTX |

## 💰 Fee Structure

- **Verification Request**: 1 STX (default)
- **Verifier Registration**: 5 STX (default)
- **Proof Validity Period**: 144 blocks (~24 hours)

## 🔐 Security Features

- ✅ Time-limited verifications prevent replay attacks
- ✅ Cryptographic proof hashes ensure data integrity
- ✅ Authorized verifier system maintains quality
- ✅ Fee-based system prevents spam
- ✅ No sensitive data stored on-chain

## 🎯 Use Cases

- 🏦 **DeFi Platforms**: Compliant lending and trading
- 🎮 **Gaming**: Age verification for restricted content
- 🏪 **E-commerce**: Trusted seller verification
- 🏛️ **Governance**: Verified voting participation
- 💼 **Professional Services**: Credential verification

## 🛠️ Development

### Testing
```bash
clarinet test
```

### Deployment
```bash
clarinet deploy --testnet
```

## 📊 Contract State

The contract maintains several data structures:
- **Authorized Verifiers**: Registered verification providers
- **Verification Requests**: Pending and completed requests
- **User Verifications**: User verification history
- **Verification Proofs**: Time-limited proof records

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📄 License

This project is licensed under the MIT License.

## 🆘 Support

For questions and support:
- Create an issue on GitHub
- Join our Discord community
- Check the documentation wiki

---



