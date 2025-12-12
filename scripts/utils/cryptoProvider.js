// SPDX-FileCopyrightText: 2025 XWiki CryptPad Team <contact@cryptpad.org> and Iulian-Tudor Scutaru
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createNaclProvider } from './providers/naclProvider.js';
import { createPQCProvider } from './providers/pqcProvider.js';
import { createElGamalProvider } from './providers/elgamalProvider.js';
import { kemSchemes, signatureSchemes, symmetricCiphers } from './schemes/cryptoSchemes.js';

export const CRYPTO_SCHEMES = {
    PQC: 'pqc',
    NACL: 'nacl',
    ELGAMAL: 'elgamal'
};

export const ENCRYPTOR_TYPES = {
    MAILBOX: 'mailbox',
    TEAM: 'team'
};

export { kemSchemes, signatureSchemes, symmetricCiphers };

export function getCryptoProvider(scheme, options = {}) {
    console.log(`[CryptoProvider] Creating provider for scheme: ${scheme} with options:`, options);

    switch (scheme) {
        case CRYPTO_SCHEMES.PQC:
            // Pass through PQC variant options
            return createPQCProvider({
                kem: options.kemVariant || 'ml-kem-1024',
                signature: options.dsaVariant || 'ml-dsa-87',
                symmetric: options.symmetric || 'aes-gcm'
            });
        case CRYPTO_SCHEMES.NACL:
            return createNaclProvider();
        case CRYPTO_SCHEMES.ELGAMAL:
            return createElGamalProvider();
        default:
            throw new Error(`Unknown crypto scheme: ${scheme}`);
    }
}

