// SPDX-FileCopyrightText: 2025 XWiki CryptPad Team <contact@cryptpad.org> and Iulian-Tudor Scutaru
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { loadCryptoModule } from './cryptoLoader.js';

export class ElGamalCryptoProvider {
    constructor() {
        this.cryptoModule = null;
        this.initialized = false;
        this.initPromise = null;
        console.log('[ElGamalProvider] Initialized ElGamal crypto provider');
    }

    async init() {
        if (this.initialized) {
            return true;
        }
        
        if (this.initPromise) {
            return this.initPromise;
        }

        this.initPromise = new Promise(async (resolve, reject) => {
            try {
                this.cryptoModule = await loadCryptoModule();
                
                this.validateCryptoModule();
                this.initialized = true;
                resolve(true);
            } catch (error) {
                console.error('[ElGamalProvider] Initialization failed:', error);
                this.initPromise = null;
                reject(error);
            }
        });

        return this.initPromise;
    }

    // ========== Utility Methods ==========

    validateCryptoModule() {
        if (!this.cryptoModule) {
            throw new Error('Failed to load chainpad_crypto module');
        }

        if (!this.cryptoModule.Nacl) {
            throw new Error('Nacl implementation not found in crypto module');
        }
    }

    async ensureInitialized() {
        if (!this.initialized) {
            await this.init();
        }
        return this.initialized;
    }
    
    async textToBytes(text) {
        await this.ensureInitialized();

        if (text === null || text === undefined) {
            return new Uint8Array(0);
        }

        if (text instanceof Uint8Array) {
            return text;
        }

        try {
            const textStr = String(text);
            if (this.cryptoModule.Nacl?.util?.decodeUTF8) {
                return this.cryptoModule.Nacl.util.decodeUTF8(textStr);
            }
            else if (this.cryptoModule.decodeUTF8) {
                return this.cryptoModule.decodeUTF8(textStr);
            }
            else {
                return new TextEncoder().encode(textStr);
            }
        } catch (err) {
            console.error('[ElGamalProvider] Error converting text to bytes:', err);
            return new Uint8Array(0);
        }
    }

    async bytesToText(bytes) {
        await this.ensureInitialized();

        if (!bytes) {
            return '';
        }

        try {
            if (this.cryptoModule.Nacl?.util?.encodeUTF8) {
                return this.cryptoModule.Nacl.util.encodeUTF8(bytes);
            }
            else if (this.cryptoModule.encodeUTF8) {
                return this.cryptoModule.encodeUTF8(bytes);
            }
            else {
                return new TextDecoder().decode(bytes);
            }
        } catch (err) {
            console.error('[ElGamalProvider] Error converting bytes to text:', err);
            return '';
        }
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

    // ========== Key Generation Methods ==========

    async generateKEMKeyPair() {
        await this.ensureInitialized();
        
        try {
            const keyPair = await window.crypto.subtle.generateKey(
                {
                    name: "ECDH",
                    namedCurve: "P-256"
                },
                true,
                ["deriveKey", "deriveBits"]
            );

            const publicKeyRaw = await window.crypto.subtle.exportKey("raw", keyPair.publicKey);
            const privateKeyRaw = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

            return {
                publicKey: this.cryptoModule.Nacl.util.encodeBase64(new Uint8Array(publicKeyRaw)),
                secretKey: this.cryptoModule.Nacl.util.encodeBase64(new Uint8Array(privateKeyRaw))
            };
        } catch (error) {
            console.error('[ElGamalProvider] Error generating KEM key pair:', error);
            
            // Fallback to NaCl for key generation if WebCrypto fails
            const keypair = this.cryptoModule.Nacl.box.keyPair();
            return {
                publicKey: this.cryptoModule.Nacl.util.encodeBase64(keypair.publicKey),
                secretKey: this.cryptoModule.Nacl.util.encodeBase64(keypair.secretKey)
            };
        }
    }

    // Use NaCl's signing function for signatures
    async generateDSAKeyPair() {
        await this.ensureInitialized();
        const keypair = this.cryptoModule.Nacl.sign.keyPair();
        return {
            publicKey: this.cryptoModule.Nacl.util.encodeBase64(keypair.publicKey),
            secretKey: this.cryptoModule.Nacl.util.encodeBase64(keypair.secretKey)
        };
    }

    // ========== ECDH Key Import Methods ==========

    async _importECDHPublicKey(base64Key) {
        try {
            const binaryKey = this.cryptoModule.Nacl.util.decodeBase64(base64Key);
            return await window.crypto.subtle.importKey(
                "raw",
                binaryKey,
                { name: "ECDH", namedCurve: "P-256" },
                false,
                []
            );
        } catch (error) {
            console.error('[ElGamalProvider] Error importing ECDH public key:', error);
            throw new Error('Failed to import recipient public key');
        }
    }

    async _importECDHPrivateKey(base64Key) {
        try {
            const binaryKey = this.cryptoModule.Nacl.util.decodeBase64(base64Key);
            return await window.crypto.subtle.importKey(
                "pkcs8",
                binaryKey,
                { name: "ECDH", namedCurve: "P-256" },
                false,
                ["deriveBits"]
            );
        } catch (error) {
            console.error('[ElGamalProvider] Error importing ECDH private key:', error);
            
            // Try alternative import format if PKCS8 fails
            try {
                const binaryKey = this.cryptoModule.Nacl.util.decodeBase64(base64Key);
                return await window.crypto.subtle.importKey(
                    "raw",
                    binaryKey,
                    { name: "ECDH", namedCurve: "P-256" },
                    false,
                    ["deriveBits"]
                );
            } catch (innerError) {
                console.error('[ElGamalProvider] Alternative key import also failed:', innerError);
                throw new Error('Failed to import private key for decryption');
            }
        }
    }

    // ========== ElGamal Mailbox Encryptor ==========

    async createMailboxEncryptor(keys) {
        await this.ensureInitialized();
        
        return {
            encrypt: async (plain, recipientPublicKey) => {
                try {
                    console.log('[ElGamalProvider] Using ElGamal hybrid encryption');

                    const ephemeralKeyPair = await window.crypto.subtle.generateKey(
                        { name: "ECDH", namedCurve: "P-256" },
                        true,
                        ["deriveBits"]
                    );

                    const recipientPubKey = await this._importECDHPublicKey(recipientPublicKey);

                    const sharedSecret = await window.crypto.subtle.deriveBits(
                        { name: "ECDH", public: recipientPubKey },
                        ephemeralKeyPair.privateKey,
                        256 // 32 bytes for AES-GCM
                    );

                    const aesKey = await window.crypto.subtle.importKey(
                        "raw",
                        sharedSecret,
                        { name: "AES-GCM", length: 256 },
                        false,
                        ["encrypt"]
                    );

                    const encoder = new TextEncoder();
                    const dataToEncrypt = typeof plain === 'string' ? encoder.encode(plain) : plain;
                    const iv = window.crypto.getRandomValues(new Uint8Array(12));
                    const ciphertext = await window.crypto.subtle.encrypt(
                        { name: "AES-GCM", iv: iv },
                        aesKey,
                        dataToEncrypt
                    );

                    const ephemeralPubKeyRaw = await window.crypto.subtle.exportKey(
                        "raw",
                        ephemeralKeyPair.publicKey
                    );

                    const signingKey = this.cryptoModule.Nacl.util.decodeBase64(keys.signingKey);
                    const messageToSign = this.concatUint8Arrays([
                        new Uint8Array(ephemeralPubKeyRaw),
                        iv,
                        new Uint8Array(ciphertext)
                    ]);
                    const signature = this.cryptoModule.Nacl.sign.detached(
                        messageToSign,
                        signingKey
                    );

                    const result = {
                        version: "elgamal-1.0",
                        ephemeralPublicKey: this.cryptoModule.Nacl.util.encodeBase64(new Uint8Array(ephemeralPubKeyRaw)),
                        iv: this.cryptoModule.Nacl.util.encodeBase64(iv),
                        ciphertext: this.cryptoModule.Nacl.util.encodeBase64(new Uint8Array(ciphertext)),
                        signature: this.cryptoModule.Nacl.util.encodeBase64(signature),
                        senderPublicKey: keys.curvePublic
                    };
                    
                    return this.cryptoModule.Nacl.util.encodeBase64(encoder.encode(JSON.stringify(result)));
                } catch (err) {
                    console.error('[ElGamalProvider] Encryption failed:', err);
                    throw err;
                }
            },
            
            decrypt: async (ciphertext, validateKey) => {
                try {
                    console.log('[ElGamalProvider] Using ElGamal hybrid decryption');
                    
                    const decoder = new TextDecoder();
                    const ciphertextBytes = this.cryptoModule.Nacl.util.decodeBase64(ciphertext);
                    const ciphertextStr = decoder.decode(ciphertextBytes);
                    const encryptedMessage = JSON.parse(ciphertextStr);

                    if (encryptedMessage.version !== "elgamal-1.0") {
                        throw new Error('Unsupported encryption version');
                    }

                    const ephemeralPubKeyBytes = this.cryptoModule.Nacl.util.decodeBase64(encryptedMessage.ephemeralPublicKey);
                    const iv = this.cryptoModule.Nacl.util.decodeBase64(encryptedMessage.iv);
                    const encryptedData = this.cryptoModule.Nacl.util.decodeBase64(encryptedMessage.ciphertext);
                    const signature = this.cryptoModule.Nacl.util.decodeBase64(encryptedMessage.signature);

                    if (validateKey) {
                        console.log('[ElGamalProvider] Verifying signature with key:', validateKey.substring(0, 10) + '...');
                        const messageToVerify = this.concatUint8Arrays([
                            ephemeralPubKeyBytes,
                            iv,
                            encryptedData
                        ]);
                        
                        const validationKeyBytes = this.cryptoModule.Nacl.util.decodeBase64(validateKey);
                        const isValid = this.cryptoModule.Nacl.sign.detached.verify(
                            messageToVerify,
                            signature,
                            validationKeyBytes
                        );
                        
                        if (!isValid) {
                            throw new Error('Invalid signature');
                        }
                        console.log('[ElGamalProvider] Signature verification successful');
                    }

                    const ephemeralPubKey = await window.crypto.subtle.importKey(
                        "raw",
                        ephemeralPubKeyBytes,
                        { name: "ECDH", namedCurve: "P-256" },
                        false,
                        []
                    );

                   const privateKey = await this._importECDHPrivateKey(keys.curvePrivate);

                    const sharedSecret = await window.crypto.subtle.deriveBits(
                        { name: "ECDH", public: ephemeralPubKey },
                        privateKey,
                        256
                    );

                    const aesKey = await window.crypto.subtle.importKey(
                        "raw",
                        sharedSecret,
                        { name: "AES-GCM", length: 256 },
                        false,
                        ["decrypt"]
                    );

                    const decrypted = await window.crypto.subtle.decrypt(
                        { name: "AES-GCM", iv: iv },
                        aesKey,
                        encryptedData
                    );
                    
                    return decoder.decode(decrypted);
                } catch (err) {
                    console.error('[ElGamalProvider] Decryption failed:', err);
                    throw err;
                }
            }
        };
    }

    // ========== Team Encryptor ==========

    async createTeamEncryptor(keys) {
        await this.ensureInitialized();

        try {
            this.validateTeamKeys(keys);

            // Check if we have the necessary keys for encryption and decryption
            const canEncrypt = !!(keys.teamCurvePublic && keys.teamEdPrivate);
            const canDecrypt = !!(keys.teamCurvePrivate && keys.teamEdPublic);

            return {
                encrypt: async (plain) => {
                    if (!canEncrypt) {
                        throw new Error('Team encryptor does not have encryption capability');
                    }

                    try {
                        console.log('[ElGamalProvider] Using ElGamal team encryption');

                        // Generate ephemeral key pair for this message
                        const ephemeralKeyPair = await window.crypto.subtle.generateKey(
                            { name: "ECDH", namedCurve: "P-256" },
                            true,
                            ["deriveBits"]
                        );

                        // Import team public key for ECDH
                        const teamPubKey = await this._importECDHPublicKey(keys.teamCurvePublic);

                        // Derive shared secret with team's public key
                        const sharedSecret = await window.crypto.subtle.deriveBits(
                            { name: "ECDH", public: teamPubKey },
                            ephemeralKeyPair.privateKey,
                            256 // 32 bytes for AES-GCM
                        );

                        // Create AES key from shared secret
                        const aesKey = await window.crypto.subtle.importKey(
                            "raw",
                            sharedSecret,
                            { name: "AES-GCM", length: 256 },
                            false,
                            ["encrypt"]
                        );

                        // Prepare data for encryption
                        const encoder = new TextEncoder();
                        const dataToEncrypt = typeof plain === 'string' ? encoder.encode(plain) : plain;
                        const iv = window.crypto.getRandomValues(new Uint8Array(12));

                        // Encrypt with AES-GCM
                        const ciphertext = await window.crypto.subtle.encrypt(
                            { name: "AES-GCM", iv: iv },
                            aesKey,
                            dataToEncrypt
                        );

                        // Export ephemeral public key
                        const ephemeralPubKeyRaw = await window.crypto.subtle.exportKey(
                            "raw",
                            ephemeralKeyPair.publicKey
                        );

                        // Sign the entire message using team's signing key
                        const signingKey = this.cryptoModule.Nacl.util.decodeBase64(keys.teamEdPrivate);
                        const messageToSign = this.concatUint8Arrays([
                            new Uint8Array(ephemeralPubKeyRaw),
                            iv,
                            new Uint8Array(ciphertext)
                        ]);
                        const signature = this.cryptoModule.Nacl.sign.detached(
                            messageToSign,
                            signingKey
                        );

                        // Create the encrypted message structure
                        const result = {
                            version: "elgamal-team-1.0",
                            ephemeralPublicKey: this.cryptoModule.Nacl.util.encodeBase64(new Uint8Array(ephemeralPubKeyRaw)),
                            iv: this.cryptoModule.Nacl.util.encodeBase64(iv),
                            ciphertext: this.cryptoModule.Nacl.util.encodeBase64(new Uint8Array(ciphertext)),
                            signature: this.cryptoModule.Nacl.util.encodeBase64(signature),
                            teamPublicKey: keys.teamCurvePublic
                        };

                        return this.cryptoModule.Nacl.util.encodeBase64(encoder.encode(JSON.stringify(result)));
                    } catch (err) {
                        console.error('[ElGamalProvider] Team encryption failed:', err);
                        throw err;
                    }
                },

                decrypt: async (ciphertext, skipValidation = false) => {
                    if (!canDecrypt) {
                        throw new Error('Team encryptor does not have decryption capability');
                    }

                    try {
                        console.log('[ElGamalProvider] Using ElGamal team decryption');

                        const decoder = new TextDecoder();
                        const ciphertextBytes = this.cryptoModule.Nacl.util.decodeBase64(ciphertext);
                        const ciphertextStr = decoder.decode(ciphertextBytes);
                        const encryptedMessage = JSON.parse(ciphertextStr);

                        if (encryptedMessage.version !== "elgamal-team-1.0") {
                            throw new Error('Unsupported team encryption version');
                        }

                        // Extract components
                        const ephemeralPubKeyBytes = this.cryptoModule.Nacl.util.decodeBase64(encryptedMessage.ephemeralPublicKey);
                        const iv = this.cryptoModule.Nacl.util.decodeBase64(encryptedMessage.iv);
                        const encryptedData = this.cryptoModule.Nacl.util.decodeBase64(encryptedMessage.ciphertext);
                        const signature = this.cryptoModule.Nacl.util.decodeBase64(encryptedMessage.signature);

                        // Verify signature if not skipping validation
                        if (!skipValidation) {
                            console.log('[ElGamalProvider] Verifying team signature');
                            const messageToVerify = this.concatUint8Arrays([
                                ephemeralPubKeyBytes,
                                iv,
                                encryptedData
                            ]);

                            const teamPublicSigningKey = this.cryptoModule.Nacl.util.decodeBase64(keys.teamEdPublic);
                            const isValid = this.cryptoModule.Nacl.sign.detached.verify(
                                messageToVerify,
                                signature,
                                teamPublicSigningKey
                            );

                            if (!isValid) {
                                throw new Error('Invalid team signature');
                            }
                            console.log('[ElGamalProvider] Team signature verification successful');
                        }

                        // Import ephemeral public key
                        const ephemeralPubKey = await window.crypto.subtle.importKey(
                            "raw",
                            ephemeralPubKeyBytes,
                            { name: "ECDH", namedCurve: "P-256" },
                            false,
                            []
                        );

                        // Import our team private key
                        const privateKey = await this._importECDHPrivateKey(keys.teamCurvePrivate);

                        // Derive the same shared secret
                        const sharedSecret = await window.crypto.subtle.deriveBits(
                            { name: "ECDH", public: ephemeralPubKey },
                            privateKey,
                            256
                        );

                        // Create AES key from shared secret
                        const aesKey = await window.crypto.subtle.importKey(
                            "raw",
                            sharedSecret,
                            { name: "AES-GCM", length: 256 },
                            false,
                            ["decrypt"]
                        );

                        // Decrypt the data
                        const decrypted = await window.crypto.subtle.decrypt(
                            { name: "AES-GCM", iv: iv },
                            aesKey,
                            encryptedData
                        );

                        const decryptedText = decoder.decode(decrypted);


                        return {
                            content: decryptedText,
                            author: 'team-member'
                        };
                    } catch (err) {
                        console.error('[ElGamalProvider] Team decryption failed:', err);
                        throw err;
                    }
                },

                can_encrypt: canEncrypt,
                can_decrypt: canDecrypt
            };
        } catch (error) {
            console.error('[ElGamalProvider] Error creating team encryptor:', error);
            throw error;
        }
    }

    // ========== Key Validation Methods ==========

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

export function createElGamalProvider() {
    return new ElGamalCryptoProvider();
}
