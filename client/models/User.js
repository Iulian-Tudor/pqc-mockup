// SPDX-FileCopyrightText: 2025 XWiki CryptPad Team <contact@cryptpad.org> and Iulian-Tudor Scutaru
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { MultiRecipientCrypto } from '../utils/multiRecipientCrypto.js';
import { getCryptoProvider, CRYPTO_SCHEMES, ENCRYPTOR_TYPES } from '../utils/cryptoProvider.js';

export class User {
    constructor(id, cryptoScheme = CRYPTO_SCHEMES.PQC, cryptoOptions = {}) {
        this.id = id;
        this.cryptoScheme = cryptoScheme;
        this.cryptoOptions = cryptoOptions;
        this.kemKeys = null;
        this.signKeys = null;
        this.multiRecipientCrypto = null;
        this.teamKeys = null;
        this.stats = [];
    }

    async init() {
        try {
            const cryptoProvider = getCryptoProvider(this.cryptoScheme, this.cryptoOptions);
            await cryptoProvider.init();

            this.kemKeys = await cryptoProvider.generateKEMKeyPair();

            this.signKeys = await cryptoProvider.generateDSAKeyPair();

            this.multiRecipientCrypto = new MultiRecipientCrypto(this, this.cryptoScheme, this.cryptoOptions);

            await this.multiRecipientCrypto.init();

            return true;
        } catch (error) {
            console.error(`[User ${this.id}] Initialization failed:`, error);
            return false;
        }
    }

    async ensureCryptoInitialized() {
        if (!this.multiRecipientCrypto) {
            this.multiRecipientCrypto = new MultiRecipientCrypto(this, this.cryptoScheme, this.cryptoOptions);
        }
        return this.multiRecipientCrypto.ensureInitialized();
    }

    async generateTeamKeys() {
        await this.ensureCryptoInitialized();
        this.teamKeys = this.multiRecipientCrypto.generateTeamKeys();
        return this.teamKeys;
    }

    async setTeamKeys(keys) {
        if (!keys) {
            console.warn(`[User ${this.id}] Attempted to set null team keys`);
            return false;
        }
        
        await this.ensureCryptoInitialized();
        this.teamKeys = keys;
        this.multiRecipientCrypto.setTeamKeys(keys);
        return true;
    }

    hasTeamKeys() {
        return !!this.teamKeys;
    }

    async encryptAndSignBlockForMany(data, recipientPublicKeys, encryptorType = ENCRYPTOR_TYPES.MAILBOX) {
        try {
            await this.ensureCryptoInitialized();

            if (encryptorType === ENCRYPTOR_TYPES.TEAM) {
                if (!this.teamKeys) {
                    throw new Error(`User ${this.id} has no team keys set for team encryption`);
                }
                this.multiRecipientCrypto.setTeamKeys(this.teamKeys);
            }

            const dataStr = typeof data === 'string' ? data : JSON.stringify(data);

            return await this.multiRecipientCrypto.createSharedBlock(dataStr, recipientPublicKeys, encryptorType);
        } catch (error) {
            console.error(`[User ${this.id}] Failed to encrypt and sign block:`, error);
            throw error;
        }
    }

    async decryptAndVerifyBlock(block) {
        try {
            await this.ensureCryptoInitialized();

            if (block.encryptorType === ENCRYPTOR_TYPES.TEAM) {
                if (block.teamKeys) {
                    this.teamKeys = block.teamKeys;
                    this.multiRecipientCrypto.setTeamKeys(block.teamKeys);
                    console.log(`[User ${this.id}] Using team keys from block for decryption`);
                } else if (this.teamKeys) {
                    console.log(`[User ${this.id}] Using existing team keys for decryption`);
                    this.multiRecipientCrypto.setTeamKeys(this.teamKeys);
                } else {
                    console.warn(`[User ${this.id}] No team keys available for team block decryption`);
                }
            }
            
            return await this.multiRecipientCrypto.decryptSharedBlock(block);
        } catch (error) {
            console.error(`[User ${this.id}] Failed to decrypt and verify block:`, error);
            throw error;
        }
    }
}

