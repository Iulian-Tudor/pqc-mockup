// SPDX-FileCopyrightText: 2025 XWiki CryptPad Team <contact@cryptpad.org> and Iulian-Tudor Scutaru
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ml_kem512, ml_kem768, ml_kem1024 } from "https://cdn.jsdelivr.net/npm/@noble/post-quantum/ml-kem/+esm";
import { ml_dsa44, ml_dsa65, ml_dsa87 } from "https://cdn.jsdelivr.net/npm/@noble/post-quantum/ml-dsa/+esm";
import { gcm } from "https://cdn.jsdelivr.net/npm/@noble/ciphers/aes/+esm";

export const kemSchemes = {
    'ml-kem-512': {
        name: 'ML-KEM-512',
        keygen: () => ml_kem512.keygen(),
        encapsulate: (pk) => ml_kem512.encapsulate(pk),
        decapsulate: (ct, sk) => ml_kem512.decapsulate(ct, sk),
        sizes: {
            publicKey: 800,
            privateKey: 1632,
            ciphertext: 768,
            sharedSecret: 32
        }
    },
    'ml-kem-768': {
        name: 'ML-KEM-768',
        keygen: () => ml_kem768.keygen(),
        encapsulate: (pk) => ml_kem768.encapsulate(pk),
        decapsulate: (ct, sk) => ml_kem768.decapsulate(ct, sk),
        sizes: {
            publicKey: 1184,
            privateKey: 2400,
            ciphertext: 1088,
            sharedSecret: 32
        }
    },
    'ml-kem-1024': {
        name: 'ML-KEM-1024',
        keygen: () => ml_kem1024.keygen(),
        encapsulate: (pk) => ml_kem1024.encapsulate(pk),
        decapsulate: (ct, sk) => ml_kem1024.decapsulate(ct, sk),
        sizes: {
            publicKey: 1568,
            privateKey: 3168,
            ciphertext: 1568,
            sharedSecret: 32
        }
    }
};

export const signatureSchemes = {
    'ml-dsa-44': {
        name: 'ML-DSA-44',
        keygen: () => ml_dsa44.keygen(),
        sign: (data, sk) => ml_dsa44.sign(sk, data),
        verify: (signature, data, pk) => ml_dsa44.verify(pk, data, signature),
        sizes: {
            publicKey: 1312,
            privateKey: 2560,
            signature: 2420
        }
    },
    'ml-dsa-65': {
        name: 'ML-DSA-65',
        keygen: () => ml_dsa65.keygen(),
        sign: (data, sk) => ml_dsa65.sign(sk, data),
        verify: (signature, data, pk) => ml_dsa65.verify(pk, data, signature),
        sizes: {
            publicKey: 1952,
            privateKey: 4000,
            signature: 3309
        }
    },
    'ml-dsa-87': {
        name: 'ML-DSA-87',
        keygen: () => ml_dsa87.keygen(),
        sign: (data, sk) => ml_dsa87.sign(sk, data),
        verify: (signature, data, pk) => ml_dsa87.verify(pk, data, signature),
        sizes: {
            publicKey: 2592,
            privateKey: 4864,
            signature: 4627
        }
    }
};

export const symmetricCiphers = {
    'aes-gcm': {
        name: 'AES-GCM',
        encrypt: (data, key) => {
            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            const ciphertext = gcm(key, iv).encrypt(data);
            const result = new Uint8Array(iv.length + ciphertext.length);
            result.set(iv);
            result.set(ciphertext, iv.length);
            return result;
        },
        decrypt: (encryptedData, key) => {
            const iv = encryptedData.slice(0, 12);
            const ciphertext = encryptedData.slice(12);
            return gcm(key, iv).decrypt(ciphertext);
        }
    }
};
