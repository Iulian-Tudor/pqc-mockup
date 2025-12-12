// SPDX-FileCopyrightText: 2025 XWiki CryptPad Team <contact@cryptpad.org> and Iulian-Tudor Scutaru
//
// SPDX-License-Identifier: AGPL-3.0-or-later
import { loadCryptoModule } from './cryptoLoader.js';

export class ElGamalCryptoProvider {
    constructor() {
        this.cryptoModule = null;
        this.initialized = false;
        this.initPromise = null;

        // ElGamal parameters - using a safe 2048-bit prime
        this.p = this.getBigIntFromHex('0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF');
        this.g = BigInt(2); // Generator

        console.log('[ElGamalProvider] Initialized actual ElGamal crypto provider');
    }

    getBigIntFromHex(hex) {
        return BigInt(hex);
    }

    bigIntToBytes(bigint, length = 256) {
        const hex = bigint.toString(16).padStart(length * 2, '0');
        const bytes = new Uint8Array(length);
        for (let i = 0; i < length; i++) {
            bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
        }
        return bytes;
    }

    bytesToBigInt(bytes) {
        let hex = '';
        for (const byte of bytes) {
            hex += byte.toString(16).padStart(2, '0');
        }
        return BigInt('0x' + hex);
    }

    // Modular exponentiation: (base^exp) % mod
    modPow(base, exponent, modulus) {
        let result = BigInt(1);
        base = base % modulus;
        while (exponent > BigInt(0)) {
            if (exponent % BigInt(2) === BigInt(1)) {
                result = (result * base) % modulus;
            }
            exponent = exponent >> BigInt(1);
            base = (base * base) % modulus;
        }
        return result;
    }

    // Generate random number in range [1, max-1]
    generateRandomBigInt(max) {
        const byteLength = Math.ceil(max.toString(2).length / 8);
        let random;
        do {
            const randomBytes = new Uint8Array(byteLength);
            crypto.getRandomValues(randomBytes);
            random = this.bytesToBigInt(randomBytes);
        } while (random >= max || random === BigInt(0));
        return random;
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
                console.log('[ElGamalProvider] ElGamal initialization complete');
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

    // ========== ElGamal Key Generation Methods ==========

    async generateKEMKeyPair() {
        await this.ensureInitialized();
        
        try {
            console.log('[ElGamalProvider] Generating actual ElGamal key pair');

            // Generate private key: random number x in [1, p-2]
            const privateKey = this.generateRandomBigInt(this.p - BigInt(1));

            // Generate public key: y = g^x mod p
            const publicKey = this.modPow(this.g, privateKey, this.p);

            // Convert to base64 for storage
            const publicKeyBytes = this.bigIntToBytes(publicKey);
            const privateKeyBytes = this.bigIntToBytes(privateKey);

            return {
                publicKey: this.cryptoModule.Nacl.util.encodeBase64(publicKeyBytes),
                secretKey: this.cryptoModule.Nacl.util.encodeBase64(privateKeyBytes)
            };
        } catch (error) {
            console.error('[ElGamalProvider] Error generating ElGamal key pair:', error);
            throw error;
        }
    }

    // Use NaCl's signing function for signatures (unchanged)
    async generateDSAKeyPair() {
        await this.ensureInitialized();
        const keypair = this.cryptoModule.Nacl.sign.keyPair();
        return {
            publicKey: this.cryptoModule.Nacl.util.encodeBase64(keypair.publicKey),
            secretKey: this.cryptoModule.Nacl.util.encodeBase64(keypair.secretKey)
        };
    }

    // ========== ElGamal Encryption/Decryption Methods ==========

    async elgamalEncrypt(publicKey, data) {
        // Convert public key from base64 to BigInt
        const publicKeyBytes = this.cryptoModule.Nacl.util.decodeBase64(publicKey);
        const y = this.bytesToBigInt(publicKeyBytes);

        // Generate random ephemeral key k
        const k = this.generateRandomBigInt(this.p - BigInt(1));

        // Calculate c1 = g^k mod p (ephemeral public key)
        const c1 = this.modPow(this.g, k, this.p);

        // Calculate shared secret: s = y^k mod p
        const sharedSecret = this.modPow(y, k, this.p);

        // Convert shared secret to AES key (first 32 bytes)
        const sharedSecretBytes = this.bigIntToBytes(sharedSecret);
        const aesKey = sharedSecretBytes.slice(0, 32);

        // Encrypt data with AES-GCM
        const key = await crypto.subtle.importKey(
            'raw',
            aesKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt']
        );

        const encoder = new TextEncoder();
        const dataBytes = typeof data === 'string' ? encoder.encode(data) : data;
        const iv = crypto.getRandomValues(new Uint8Array(12));

        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            dataBytes
        );

        return {
            c1: this.bigIntToBytes(c1), // Ephemeral public key
            iv: iv,
            ciphertext: new Uint8Array(ciphertext)
        };
    }

    async elgamalDecrypt(privateKey, encryptedData) {
        const { c1, iv, ciphertext } = encryptedData;

        // Convert private key from base64 to BigInt
        const privateKeyBytes = this.cryptoModule.Nacl.util.decodeBase64(privateKey);
        const x = this.bytesToBigInt(privateKeyBytes);

        // Convert c1 back to BigInt
        const c1BigInt = this.bytesToBigInt(c1);

        // Calculate shared secret: s = c1^x mod p
        const sharedSecret = this.modPow(c1BigInt, x, this.p);

        // Convert shared secret to AES key
        const sharedSecretBytes = this.bigIntToBytes(sharedSecret);
        const aesKey = sharedSecretBytes.slice(0, 32);

        // Decrypt with AES-GCM
        const key = await crypto.subtle.importKey(
            'raw',
            aesKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt']
        );

        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            ciphertext
        );

        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    }

    // ========== ElGamal Mailbox Encryptor ==========

    async createMailboxEncryptor(keys) {
        await this.ensureInitialized();
        
        return {
            encrypt: async (plain, recipientPublicKey) => {
                try {
                    console.log('[ElGamalProvider] Using actual ElGamal encryption');

                    const encryptedData = await this.elgamalEncrypt(recipientPublicKey, plain);

                    // Sign the encrypted data with NaCl
                    const signingKey = this.cryptoModule.Nacl.util.decodeBase64(keys.signingKey);
                    const messageToSign = this.concatUint8Arrays([
                        encryptedData.c1,
                        encryptedData.iv,
                        encryptedData.ciphertext
                    ]);
                    const signature = this.cryptoModule.Nacl.sign.detached(
                        messageToSign,
                        signingKey
                    );

                    const result = {
                        version: "elgamal-aes-1.0",
                        c1: this.cryptoModule.Nacl.util.encodeBase64(encryptedData.c1),
                        iv: this.cryptoModule.Nacl.util.encodeBase64(encryptedData.iv),
                        ciphertext: this.cryptoModule.Nacl.util.encodeBase64(encryptedData.ciphertext),
                        signature: this.cryptoModule.Nacl.util.encodeBase64(signature),
                        senderPublicKey: keys.curvePublic
                    };
                    
                    const encoder = new TextEncoder();
                    return this.cryptoModule.Nacl.util.encodeBase64(encoder.encode(JSON.stringify(result)));
                } catch (err) {
                    console.error('[ElGamalProvider] ElGamal encryption failed:', err);
                    throw err;
                }
            },
            
            decrypt: async (ciphertext, validateKey) => {
                try {
                    console.log('[ElGamalProvider] Using actual ElGamal decryption');

                    const decoder = new TextDecoder();
                    const ciphertextBytes = this.cryptoModule.Nacl.util.decodeBase64(ciphertext);
                    const ciphertextStr = decoder.decode(ciphertextBytes);
                    const encryptedMessage = JSON.parse(ciphertextStr);

                    if (!encryptedMessage.version?.startsWith("elgamal-aes-")) {
                        throw new Error('Unsupported encryption version');
                    }

                    const c1 = this.cryptoModule.Nacl.util.decodeBase64(encryptedMessage.c1);
                    const iv = this.cryptoModule.Nacl.util.decodeBase64(encryptedMessage.iv);
                    const encryptedData = this.cryptoModule.Nacl.util.decodeBase64(encryptedMessage.ciphertext);
                    const signature = this.cryptoModule.Nacl.util.decodeBase64(encryptedMessage.signature);

                    // Verify signature if validation key provided
                    if (validateKey) {
                        console.log('[ElGamalProvider] Verifying signature');
                        const messageToVerify = this.concatUint8Arrays([c1, iv, encryptedData]);
                        const validationKeyBytes = this.cryptoModule.Nacl.util.decodeBase64(validateKey);
                        const isValid = this.cryptoModule.Nacl.sign.detached.verify(
                            messageToVerify,
                            signature,
                            validationKeyBytes
                        );
                        
                        if (!isValid) {
                            throw new Error('Invalid signature');
                        }
                    }

                    // Decrypt using ElGamal
                    const decryptedData = await this.elgamalDecrypt(keys.curvePrivate, {
                        c1: c1,
                        iv: iv,
                        ciphertext: encryptedData
                    });

                    return decryptedData;
                } catch (err) {
                    console.error('[ElGamalProvider] ElGamal decryption failed:', err);
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

            const canEncrypt = !!(keys.teamCurvePublic && keys.teamEdPrivate);
            const canDecrypt = !!(keys.teamCurvePrivate && keys.teamEdPublic);

            return {
                encrypt: async (plain) => {
                    if (!canEncrypt) {
                        throw new Error('Team encryptor does not have encryption capability');
                    }

                    const encryptedData = await this.elgamalEncrypt(keys.teamCurvePublic, plain);

                    let signingKey;
                    try {
                        signingKey = this.cryptoModule.Nacl.util.decodeBase64(keys.teamEdPrivate);
                        if (signingKey.length !== 64) {
                            throw new Error('Invalid team signing key format');
                        }
                    } catch (error) {
                        throw new Error(`Team encryption failed: invalid signing key - ${error.message}`);
                    }

                    const messageToSign = this.concatUint8Arrays([
                        encryptedData.c1,
                        encryptedData.iv,
                        encryptedData.ciphertext
                    ]);

                    const signature = this.cryptoModule.Nacl.sign.detached(
                        messageToSign,
                        signingKey
                    );

                    const result = {
                        version: "elgamal-team-aes-1.0",
                        c1: this.cryptoModule.Nacl.util.encodeBase64(encryptedData.c1),
                        iv: this.cryptoModule.Nacl.util.encodeBase64(encryptedData.iv),
                        ciphertext: this.cryptoModule.Nacl.util.encodeBase64(encryptedData.ciphertext),
                        signature: this.cryptoModule.Nacl.util.encodeBase64(signature),
                        teamPublicKey: keys.teamCurvePublic
                    };

                    const encoder = new TextEncoder();
                    return this.cryptoModule.Nacl.util.encodeBase64(encoder.encode(JSON.stringify(result)));
                },

                decrypt: async (ciphertext, skipValidation = false) => {
                    if (!canDecrypt) {
                        throw new Error('Team encryptor does not have decryption capability');
                    }

                    console.log('[ElGamalProvider] Using ElGamal team decryption');

                    const decoder = new TextDecoder();
                    const ciphertextBytes = this.cryptoModule.Nacl.util.decodeBase64(ciphertext);
                    const ciphertextStr = decoder.decode(ciphertextBytes);
                    const encryptedMessage = JSON.parse(ciphertextStr);

                    if (!encryptedMessage.version?.startsWith("elgamal-team-aes-")) {
                        throw new Error('Unsupported team encryption version');
                    }

                    const c1 = this.cryptoModule.Nacl.util.decodeBase64(encryptedMessage.c1);
                    const iv = this.cryptoModule.Nacl.util.decodeBase64(encryptedMessage.iv);
                    const encryptedData = this.cryptoModule.Nacl.util.decodeBase64(encryptedMessage.ciphertext);
                    const signature = this.cryptoModule.Nacl.util.decodeBase64(encryptedMessage.signature);

                    // Verify team signature if not skipping validation
                    if (!skipValidation) {
                        const messageToVerify = this.concatUint8Arrays([c1, iv, encryptedData]);
                        const teamPublicSigningKey = this.cryptoModule.Nacl.util.decodeBase64(keys.teamEdPublic);

                        if (teamPublicSigningKey.length !== 32) {
                            throw new Error('Invalid team public key format');
                        }

                        const isValid = this.cryptoModule.Nacl.sign.detached.verify(
                            messageToVerify,
                            signature,
                            teamPublicSigningKey
                        );

                        if (!isValid) {
                            throw new Error('Invalid team signature');
                        }
                    }

                    // Decrypt using ElGamal
                    let decryptedText;
                    try {
                        decryptedText = await this.elgamalDecrypt(keys.teamCurvePrivate, {
                            c1: c1,
                            iv: iv,
                            ciphertext: encryptedData
                        });
                    } catch (decryptError) {
                        if (decryptError.name === 'OperationError' || decryptError instanceof DOMException) {
                            throw new Error('Team decryption failed: wrong team keys or corrupted data');
                        }
                        throw new Error(`Team decryption failed: ${decryptError.message}`);
                    }

                    return {
                        content: decryptedText,
                        author: 'team-member'
                    };
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
