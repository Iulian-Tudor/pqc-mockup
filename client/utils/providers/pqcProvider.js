// SPDX-FileCopyrightText: 2025 XWiki CryptPad Team <contact@cryptpad.org> and Iulian-Tudor Scutaru
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { kemSchemes, signatureSchemes, symmetricCiphers } from '../schemes/cryptoSchemes.js';

// Variant configurations
const KEM_VARIANTS = {
    'ml-kem-512': 'ml-kem-512',
    'ml-kem-768': 'ml-kem-768',
    'ml-kem-1024': 'ml-kem-1024'
};

const DSA_VARIANTS = {
    'ml-dsa-44': 'ml-dsa-44',
    'ml-dsa-65': 'ml-dsa-65',
    'ml-dsa-87': 'ml-dsa-87'
};

export class PQCProvider {
    constructor(options = {}) {
        this.initialized = false;

        // Validate and set KEM variant
        const kemVariant = options.kem || 'ml-kem-1024';
        if (!KEM_VARIANTS[kemVariant]) {
            throw new Error(`Invalid KEM variant: ${kemVariant}. Available: ${Object.keys(KEM_VARIANTS).join(', ')}`);
        }

        // Validate and set DSA variant
        const dsaVariant = options.signature || 'ml-dsa-87';
        if (!DSA_VARIANTS[dsaVariant]) {
            throw new Error(`Invalid DSA variant: ${dsaVariant}. Available: ${Object.keys(DSA_VARIANTS).join(', ')}`);
        }

        this.kemScheme = kemSchemes[kemVariant];
        this.signatureScheme = signatureSchemes[dsaVariant];
        this.symmetricCipher = symmetricCiphers[options.symmetric || 'aes-gcm'];

        this.kemVariant = kemVariant;
        this.dsaVariant = dsaVariant;

        console.log(`[PQCProvider] Initialized with ${kemVariant} + ${dsaVariant}`);

        if (!this.kemScheme) throw new Error(`KEM scheme ${kemVariant} not found`);
        if (!this.signatureScheme) throw new Error(`Signature scheme ${dsaVariant} not found`);
        if (!this.symmetricCipher) throw new Error('Invalid symmetric cipher specified');
    }

    getVariantInfo() {
        return {
            kem: this.kemVariant,
            signature: this.dsaVariant,
            kemSizes: this.kemScheme.sizes || {},
            signatureSizes: this.signatureScheme.sizes || {}
        };
    }

    async init() {
        this.initialized = true;
        return true;
    }

    // ========== Utility Methods ==========

    textToBytes(text) {
        if (text instanceof Uint8Array) return text;
        return new TextEncoder().encode(text);
    }

    bytesToText(bytes) {
        return new TextDecoder().decode(bytes);
    }

    encodeBase64(bytes) {
        return btoa(String.fromCharCode.apply(null, bytes));
    }

    decodeBase64(str) {
        return new Uint8Array(
            atob(str).split('').map(c => c.charCodeAt(0))
        );
    }

    concatUint8Arrays(arrays) {
        const totalLength = arrays.reduce((acc, arr) => acc + arr.length, 0);
        const result = new Uint8Array(totalLength);
        let offset = 0;
        for (const array of arrays) {
            result.set(array, offset);
            offset += array.length;
        }
        return result;
    }

    _ensureUint8Array(data) {
        return data instanceof Uint8Array ? data : new Uint8Array(data);
    }

    // ========== Key Generation Methods ==========

    generateKEMKeyPair() {
        return this.kemScheme.keygen();
    }

    generateDSAKeyPair() {
        return this.signatureScheme.keygen();
    }

    // ========== Key Encapsulation Methods ==========

    encapsulateSecret(publicKey) {
        const pk = this._ensureUint8Array(publicKey);
        return this.kemScheme.encapsulate(pk);
    }

    decapsulateSecret(ciphertext, secretKey) {
        const ct = this._ensureUint8Array(ciphertext);
        const sk = this._ensureUint8Array(secretKey);
        return this.kemScheme.decapsulate(ct, sk);
    }

    // ========== Symmetric Encryption Methods ==========

    encryptData(data, sharedSecret) {
        const dataBytes = data instanceof Uint8Array ? data : this.textToBytes(data);
        const key = sharedSecret.slice(0, 32);
        const encrypted = this.symmetricCipher.encrypt(dataBytes, key);
        return this.encodeBase64(encrypted);
    }

    decryptData(encryptedData, sharedSecret) {
        try {
            const encryptedBytes = this.decodeBase64(encryptedData);
            const key = sharedSecret.slice(0, 32);
            const decryptedBytes = this.symmetricCipher.decrypt(encryptedBytes, key);
            return this.bytesToText(decryptedBytes);
        } catch (error) {
            console.error(`[PQC] ${this.symmetricCipher.name} Decryption error:`, error);
            throw new Error(`${this.symmetricCipher.name} Decryption failed: ${error.message}`);
        }
    }

    // ========== Digital Signature Methods ==========

    signData(data, secretKey) {
        const sk = this._ensureUint8Array(secretKey);
        const dataBytes = data instanceof Uint8Array ? data : this.textToBytes(data);
        return this.signatureScheme.sign(sk, dataBytes);
    }

    verifySignature(signature, data, publicKey) {
        const sig = this._ensureUint8Array(signature);
        const dataBytes = data instanceof Uint8Array ? data : this.textToBytes(data);
        const pubKey = this._ensureUint8Array(publicKey);
        return this.signatureScheme.verify(pubKey, dataBytes, sig);
    }

    // ========== Encryptor Creation Methods ==========

    createMailboxEncryptor(keys) {
        const provider = this;

        return {
            encrypt: async function(data, recipientPublicKey) {
                const { cipherText, sharedSecret } = await provider.encapsulateSecret(recipientPublicKey);

                const dataToEncrypt = typeof data === 'string' ? data : provider.bytesToText(data);
                const encryptedData = provider.encryptData(dataToEncrypt, sharedSecret);

                const signature = await provider.signData(
                    typeof data === 'string' ? provider.textToBytes(data) : data,
                    keys.signingKey
                );

                return {
                    encryptedData,
                    ciphertext: cipherText,
                    signature,
                    senderPublicKey: keys.curvePublic,
                    dataType: typeof data === 'string' ? 'string' : 'binary'
                };
            },

            decrypt: async function(message, senderPublicKey) {
                const { encryptedData, ciphertext, signature, dataType } = message;

                try {
                    const sharedSecret = await provider.decapsulateSecret(ciphertext, keys.curvePrivate);

                    const decryptedText = provider.decryptData(encryptedData, sharedSecret);

                    const decryptedData = dataType === 'string' ?
                        decryptedText : provider.textToBytes(decryptedText);

                    const dataForVerification = dataType === 'string' ?
                        provider.textToBytes(decryptedText) : decryptedData;
                    const isValid = await provider.verifySignature(signature, dataForVerification, senderPublicKey);

                    if (!isValid) {
                        throw new Error('Invalid signature');
                    }

                    return decryptedData;
                } catch (error) {
                    console.error('[PQC Mailbox] Decryption failed:', error);
                    throw new Error(`Decryption failed: ${error.message}`);
                }
            }
        };
    }

    createTeamEncryptor(keys) {
        this.validateTeamKeys(keys);
        const provider = this;

        const canEncrypt = true;
        const canDecrypt = true;
        
        return {
            encrypt: async function(data) {
                try {
                    return await provider.teamEncrypt(data, keys);
                } catch (error) {
                    console.error('[PQC Team Encryptor] Encryption failed:', error);
                    throw new Error(`Team encryption failed: ${error.message}`);
                }
            },
            
            decrypt: async function(message, skipValidation = false) {
                try {
                    return await provider.teamDecrypt(message, keys, skipValidation);
                } catch (error) {
                    console.error('[PQC Team Encryptor] Decryption failed:', error);
                    throw new Error(`Team decryption failed: ${error.message}`);
                }
            },

            can_encrypt: canEncrypt,
            can_decrypt: canDecrypt
        };
    }

    // ========== Team Encryption Methods ==========

    async teamEncrypt(data, keys) {
        const dataBytes = typeof data === 'string' ? this.textToBytes(data) : data;

        // Inner encryption layer
        const innerEncapsulation = await this.encapsulateSecret(keys.teamCurvePublic);
        const innerEncrypted = this.encryptData(dataBytes, innerEncapsulation.sharedSecret);

        // Create inner bundle with author information
        const innerBundle = {
            authorPublicKey: keys.myCurvePublic,
            encryptedData: innerEncrypted,
            ciphertext: this.encodeBase64(innerEncapsulation.cipherText)
        };
        const innerBundleBytes = this.textToBytes(JSON.stringify(innerBundle));

        // Outer encryption layer
        const ephemeralKeypair = await this.generateKEMKeyPair();
        const outerEncapsulation = await this.encapsulateSecret(keys.teamCurvePublic);
        const outerEncrypted = this.encryptData(innerBundleBytes, outerEncapsulation.sharedSecret);

        // Create outer bundle with ephemeral key
        const outerBundle = {
            encryptedData: outerEncrypted,
            ciphertext: this.encodeBase64(outerEncapsulation.cipherText),
            ephemeralPublicKey: ephemeralKeypair.publicKey
        };

        // Sign the entire outer bundle
        const outerBundleBytes = this.textToBytes(JSON.stringify(outerBundle));
        const signature = await this.signData(outerBundleBytes, keys.teamEdPrivate);

        return {
            outerBundle: outerBundle,
            signature: this.encodeBase64(signature)
        };
    }

    async teamDecrypt(message, keys, skipValidation) {
        try {
            const { outerBundle, signature } = message;

            // Validate signature if required
            if (!skipValidation) {
                const outerBundleBytes = this.textToBytes(JSON.stringify(outerBundle));
                const signatureBytes = this.decodeBase64(signature);
                const isValid = await this.verifySignature(
                    signatureBytes, 
                    outerBundleBytes, 
                    keys.teamEdPublic
                );
                
                if (!isValid) {
                    throw new Error('Invalid team signature');
                }
            }

            // Decrypt outer layer
            const outerCiphertext = this.decodeBase64(outerBundle.ciphertext);
            const outerSharedSecret = await this.decapsulateSecret(
                outerCiphertext, 
                keys.teamCurvePrivate
            );
            const decryptedOuterBundle = this.decryptData(
                outerBundle.encryptedData, 
                outerSharedSecret
            );

            // Parse inner bundle
            const innerBundle = JSON.parse(decryptedOuterBundle);

            // Decrypt inner layer
            const innerCiphertext = this.decodeBase64(innerBundle.ciphertext);
            const innerSharedSecret = await this.decapsulateSecret(
                innerCiphertext,
                keys.teamCurvePrivate
            );
            const decryptedData = this.decryptData(
                innerBundle.encryptedData, 
                innerSharedSecret
            );

            return {
                content: decryptedData,
                author: innerBundle.authorPublicKey
            };
        } catch (error) {
            console.error('[PQC Team] Decryption failed:', error);
            throw new Error(`Team decryption failed: ${error.message}`);
        }
    }

    validateTeamKeys(keys) {
        const requiredKeys = [
            'teamCurvePublic', 'teamCurvePrivate',
            'teamEdPublic', 'teamEdPrivate',
            'myCurvePublic', 'myCurvePrivate'
        ];
        
        const missingKeys = requiredKeys.filter(key => !keys[key]);
        if (missingKeys.length > 0) {
            throw new Error(`Missing required team keys: ${missingKeys.join(', ')}`);
        }

        return true;
    }
}

export function createPQCProvider(options = {}) {
    return new PQCProvider(options);
}
