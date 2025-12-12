<!--
SPDX-FileCopyrightText: 2025 XWiki CryptPad Team <contact@cryptpad.org> and Iulian-Tudor Scutaru

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Post-Quantum Cryptography Mockup

A simulation environment for testing and benchmarking post-quantum cryptography implementations against traditional cryptographic methods with modular algorithm selection.

## Overview

This project provides a comprehensive sandbox for experimenting with post-quantum cryptographic algorithms, including all three variants of ML-KEM and ML-DSA, compared to traditional elliptic curve cryptography (NaCl) and hybrid ElGamal implementations. It simulates a collaborative document editing environment where users encrypt, decrypt, sign, and verify messages, allowing for detailed performance and security analysis.

## Features

- **Triple Cryptography Support**: Post-quantum (ML-KEM/ML-DSA), traditional (NaCl), and traditional (ElGamal+AES)
- **Modular Algorithm Selection**: Choose from 3 ML-KEM variants (512, 768, 1024) and 3 ML-DSA variants (44, 65, 87)
- **Universal Encryption Support**: All providers implement both mailbox and team encryption modes
- **Realistic Simulation**: Models collaborative document editing with configurable parameters
- **Performance Analytics**: Collects and visualizes encryption, decryption, signing, and verification times
- **Configurable Environment**: Easily modify user counts, document distribution, activity levels, and crypto variants

## Cryptography Implementations

### Post-Quantum Provider (`pqcProvider.js`)
- **ML-KEM variants**: ml-kem-512 (128-bit), ml-kem-768 (192-bit), ml-kem-1024 (256-bit)
- **ML-DSA variants**: ml-dsa-44 (128-bit), ml-dsa-65 (192-bit), ml-dsa-87 (256-bit)
- **Symmetric encryption**: AES-GCM for data encryption
- **Supports**: Mailbox and team encryption modes

### Traditional Provider (`naclProvider.js`)
- **Asymmetric**: Curve25519 for encryption, Ed25519 for signatures
- **Compatible**: Uses chainpad_crypto for established CryptPad encryption patterns
- **Supports**: Mailbox and team encryption modes

### Hybrid ElGamal Provider (`elgamalProvider.js`)
- **Key exchange**: ECDH (P-256) for key establishment
- **Symmetric**: AES-GCM for data encryption
- **Signatures**: Ed25519 (NaCl) for message authentication
- **Supports**: Mailbox and team encryption modes

## Architecture

The system is built around these core components:

- **Crypto Providers**: Modular implementations of cryptographic primitives
- **User Model**: Simulates users with their own key pairs who perform cryptographic operations
- **Document Model**: Represents shared documents with multiple editors
- **Document Server**: Facilitates message broadcasting between users
- **Simulation Engine**: Orchestrates the entire simulation process

## Usage

### Running a Simulation

```javascript
import { runSimulation } from './scripts/simulation/Simulation.js';

// Configure the simulation parameters
const simulationParams = {
    numUsers: 30,
    numDocuments: 30,
    maxEditsPerUser: 100,
    logFrequency: 20,
    useDistribution: true,
    cryptoScheme: 'pqc',  // 'pqc', 'nacl', or 'elgamal'
    encryptorType: 'mailbox',  // 'mailbox' or 'team'
    // PQC-specific variant selection
    kem: 'ml-kem-1024',      // 'ml-kem-512', 'ml-kem-768', 'ml-kem-1024'
    signature: 'ml-dsa-87'    // 'ml-dsa-44', 'ml-dsa-65', 'ml-dsa-87'
};

// Run the simulation
const results = await runSimulation(simulationParams);
```

### Simulation Parameters

- `numUsers`: Number of users to create
- `numDocuments`: Number of documents to create
- `maxEditsPerUser`: Maximum number of edits per user
- `logFrequency`: How often to log progress
- `useDistribution`: Whether to use statistical distributions for realistic user behavior
- `cryptoScheme`: Cryptography implementation to use ('pqc', 'nacl', or 'elgamal')
- `encryptorType`: Encryption model to use ('mailbox' or 'team')
- `kem`: ML-KEM variant for PQC ('ml-kem-512', 'ml-kem-768', 'ml-kem-1024')
- `signature`: ML-DSA variant for PQC ('ml-dsa-44', 'ml-dsa-65', 'ml-dsa-87')

### PQC Variant Selection

The post-quantum provider supports modular selection of algorithm variants:

**ML-KEM (Key Encapsulation Mechanism)**
- `ml-kem-512`: 128-bit security, 800B public keys, fastest
- `ml-kem-768`: 192-bit security, 1184B public keys, balanced
- `ml-kem-1024`: 256-bit security, 1568B public keys, strongest

**ML-DSA (Digital Signature Algorithm)**
- `ml-dsa-44`: 128-bit security, 2420B signatures, fastest
- `ml-dsa-65`: 192-bit security, 3309B signatures, balanced
- `ml-dsa-87`: 256-bit security, 4627B signatures, strongest

## Performance Considerations

When running simulations:

1. **Post-quantum algorithms** have varying performance characteristics:
   - Smaller variants (512/44) are faster but provide lower security
   - Larger variants (1024/87) are slower but provide maximum security
   - 768/65 variants offer a good balance between security and performance
2. **Team-based encryption** reduces the number of encryption operations but may have higher initial overhead
3. **All three providers** (PQC, NaCl, ElGamal) support both mailbox and team encryption modes
4. For large simulations, consider increasing log frequency to reduce UI updates

## Implementation Details

### Universal Encryption Support

All three cryptographic providers implement both encryption paradigms:

1. **Mailbox encryption**: Each message is individually encrypted for each recipient
   - Available in: PQC, NaCl, and ElGamal providers
   - Best for: Direct user-to-user communication, variable recipient lists
2. **Team encryption**: Messages are encrypted once with shared team keys
   - Available in: PQC, NaCl, and ElGamal providers  
   - Best for: Collaborative document editing, stable team membership

### Hybrid Encryption Process

For all providers, the encryption process works in layers:

1. Generate or retrieve asymmetric key pairs
2. Perform key encapsulation (PQC), key exchange (ElGamal), or use established patterns (NaCl)
3. Use the resulting shared secret for symmetric encryption (AES-GCM for PQC/ElGamal, built-in for NaCl)
4. Sign the message with the sender's private signing key

## Development

### Adding New Crypto Providers

To implement a new cryptographic provider:

1. Create a new provider class implementing the required methods
2. Register it in `cryptoProvider.js`
3. Update the `CRYPTO_SCHEMES` enum with the new scheme name

Required provider methods: (maintain name for compatibility with existing code)
- `init()`
- `generateKEMKeyPair()`
- `generateDSAKeyPair()`
- `createMailboxEncryptor(keys)`
- `createTeamEncryptor(keys)`

### Future Improvements

- Add support for additional post-quantum algorithms
- Add more detailed analysis of message sizes and bandwidth usage
- Create visual comparisons of cryptographic performance
- Add automated testing suite for cryptographic correctness

## License

This project is provided as is under the GNU Affero General Public License v3.0.
