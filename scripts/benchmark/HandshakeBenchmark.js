// SPDX-FileCopyrightText: 2025 XWiki CryptPad Team <contact@cryptpad.org> and Iulian-Tudor Scutaru
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { NetworkSimulator, NETWORK_PROFILES } from './NetworkSimulator.js';

/**
 * Handshake Benchmarking for Post-Quantum Cryptography
 * 
 * This module implements two key exchange protocols:
 * 1. Hybrid Handshake (X25519 + Kyber-768)
 * 2. Pure PQC "2-KEM" (Mutual Kyber-768)
 * 3. Hybrid "2-KEM" (X25519 + Mutual Kyber-768)
 * 4. Pure ECDH (X25519 only)
 * 
 */
export class HandshakeBenchmark {
    constructor(options = {}) {
        this.iterations = options.iterations || 30000;
        this.warmupIterations = options.warmupIterations || 1000;
        this.networkProfile = options.networkProfile || NETWORK_PROFILES.HIGH_SPEED;
        this.logCallback = options.logCallback || console.log;
        
        this.kyber = null;
        this.nacl = null;
        
        this.results = {
            ecdh: null,
            hybrid: null,
            twoKEM: null,
            hybrid2KEM: null
        };
    }

    async init() {
        this.logCallback('Initializing cryptographic libraries...');
        
        try {
            if (typeof window !== 'undefined') {
                this.kyber = await this.loadNoblePostQuantum();
            } else {
                const { ml_kem768 } = await import('@noble/post-quantum/ml-kem');
                this.kyber = ml_kem768;
            }
            
            if (typeof window !== 'undefined' && window.nacl) {
                this.nacl = window.nacl;
            } else {
                const naclModule = await import('tweetnacl');
                this.nacl = naclModule.default || naclModule;
            }
            
            this.logCallback('Cryptographic libraries loaded successfully');
            return true;
        } catch (error) {
            this.logCallback(`Failed to load crypto libraries: ${error.message}`);
            throw error;
        }
    }

    async loadNoblePostQuantum() {
        if (window.noblePostQuantum && window.noblePostQuantum.ml_kem768) {
            return window.noblePostQuantum.ml_kem768;
        }

        try {
            const mlKem = await import('https://esm.sh/@noble/post-quantum@0.4.0/ml-kem');
            window.noblePostQuantum = { ml_kem768: mlKem.ml_kem768 };
            return mlKem.ml_kem768;
        } catch (error) {
            throw new Error(`Failed to load @noble/post-quantum: ${error.message}`);
        }
    }

    async runAll() {
        await this.init();
        
        this.logCallback('\n=== Starting PQC Handshake Benchmarks ===');
        this.logCallback(`Network Profile: ${this.networkProfile.name}`);
        this.logCallback(`Iterations: ${this.iterations.toLocaleString()} (+ ${this.warmupIterations.toLocaleString()} warm-up)`);
        this.logCallback('');
        
        this.logCallback('--- Protocol A: Pure ECDH (X25519 only) ---');
        this.results.ecdh = await this.runECDHBenchmark();
        
        this.logCallback('');
        
        this.logCallback('--- Protocol B: Hybrid Handshake (X25519 + Kyber-768) ---');
        this.results.hybrid = await this.runHybridBenchmark();
        
        this.logCallback('');
        
        this.logCallback('--- Protocol C: Pure PQC "2-KEM" (Mutual Kyber-768) ---');
        this.results.twoKEM = await this.run2KEMBenchmark();
        
        this.logCallback('');
        
        this.logCallback('--- Protocol D: Hybrid "2-KEM" (X25519 + Mutual Kyber-768) ---');
        this.results.hybrid2KEM = await this.runHybrid2KEMBenchmark();
        
        this.logCallback('');
        
        this.displayComparison();
        
        return this.results;
    }

    /**
     * Protocol A: Pure ECDH (X25519 only)
     * 
     * Classic Diffie-Hellman key exchange:
     * 1. Alice generates ephemeral X25519 keypair
     * 2. Alice -> Bob: X25519 PubKey
     * 3. Bob generates X25519 keypair, calculates shared secret
     * 4. Bob -> Alice: X25519 PubKey
     * 5. Alice calculates shared secret
     * 6. Result: X25519 shared secret
     */
    async runECDHBenchmark() {
        const networkSim = new NetworkSimulator(this.networkProfile);
        
        this.logCallback(`Warming up JIT (${this.warmupIterations} iterations)...`);
        for (let i = 0; i < this.warmupIterations; i++) {
            await this.ecdhHandshakeOnce();
        }
        
        this.logCallback('Running benchmark...');
        const startTime = performance.now();
        
        let totalPayload1Size = 0;
        let totalPayload2Size = 0;
        let totalNetworkDelay = 0;
        
        for (let i = 0; i < this.iterations; i++) {
            const result = await this.ecdhHandshakeOnce();
            
            const delay1 = await networkSim.simulateTransmission(result.payload1Size);
            const delay2 = await networkSim.simulateTransmission(result.payload2Size);
            
            totalPayload1Size += result.payload1Size;
            totalPayload2Size += result.payload2Size;
            totalNetworkDelay += delay1 + delay2;
            
            if ((i + 1) % 100 === 0) {
                await new Promise(resolve => setTimeout(resolve, 0));
            }
            
            if ((i + 1) % 5000 === 0) {
                this.logCallback(`  Progress: ${(i + 1).toLocaleString()} / ${this.iterations.toLocaleString()}`);
            }
        }
        
        const endTime = performance.now();
        const totalTime = endTime - startTime;
        
        const results = {
            protocol: 'Pure ECDH (X25519)',
            totalTime: { value: totalTime, unit: 'ms' },
            avgTimePerHandshake: { value: totalTime / this.iterations, unit: 'ms' },
            avgPayload1Size: { value: totalPayload1Size / this.iterations, unit: 'bytes' },
            avgPayload2Size: { value: totalPayload2Size / this.iterations, unit: 'bytes' },
            totalPayloadSize: { value: (totalPayload1Size + totalPayload2Size) / this.iterations, unit: 'bytes' },
            avgNetworkDelay: { value: totalNetworkDelay / this.iterations, unit: 'ms' },
            iterations: this.iterations
        };
        
        this.logCallback(`Completed in ${(totalTime / 1000).toFixed(2)}s`);
        this.logCallback(`  Avg time/handshake: ${results.avgTimePerHandshake.value.toFixed(4)}ms`);
        this.logCallback(`  Avg payload size: ${results.totalPayloadSize.value.toFixed(0)} bytes`);
        this.logCallback(`  Avg network delay: ${results.avgNetworkDelay.value.toFixed(4)}ms`);
        
        return results;
    }

    async ecdhHandshakeOnce() {
        const aliceX25519 = this.nacl.box.keyPair();
        
        const payload1 = aliceX25519.publicKey; // 32 bytes
        
        const bobX25519 = this.nacl.box.keyPair();
        const bobSharedSecret = this.nacl.scalarMult(
            bobX25519.secretKey,
            aliceX25519.publicKey
        );
        
        const payload2 = bobX25519.publicKey; // 32 bytes
        
        const aliceSharedSecret = this.nacl.scalarMult(
            aliceX25519.secretKey,
            bobX25519.publicKey
        );
        
        return {
            payload1Size: payload1.length,
            payload2Size: payload2.length,
            sharedSecret: aliceSharedSecret
        };
    }

    /**
     * Protocol B: Hybrid Handshake (X25519 + Kyber-768)
     * 
     * Steps:
     * 1. Alice generates ephemeral X25519 + Kyber keypairs
     * 2. Alice -> Bob: X25519 PubKey + Kyber PubKey
     * 3. Bob generates X25519 keypair, calculates X25519 shared secret, encapsulates Kyber secret
     * 4. Bob -> Alice: X25519 PubKey + Kyber Ciphertext
     * 5. Alice calculates X25519 shared secret, decapsulates Kyber secret
     * 6. Result: Concatenated shared secrets
     */
    async runHybridBenchmark() {
        const networkSim = new NetworkSimulator(this.networkProfile);
        
        this.logCallback(`Warming up JIT (${this.warmupIterations} iterations)...`);
        for (let i = 0; i < this.warmupIterations; i++) {
            await this.hybridHandshakeOnce();
        }
        
        this.logCallback('Running benchmark...');
        const startTime = performance.now();
        
        let totalPayload1Size = 0;
        let totalPayload2Size = 0;
        let totalNetworkDelay = 0;
        
        for (let i = 0; i < this.iterations; i++) {
            const result = await this.hybridHandshakeOnce();
            
            const delay1 = await networkSim.simulateTransmission(result.payload1Size);
            const delay2 = await networkSim.simulateTransmission(result.payload2Size);
            
            totalPayload1Size += result.payload1Size;
            totalPayload2Size += result.payload2Size;
            totalNetworkDelay += delay1 + delay2;
            
            // Progress indicator and yield to browser event loop every 100 iterations
            if ((i + 1) % 100 === 0) {
                await new Promise(resolve => setTimeout(resolve, 0));
            }
            
            if ((i + 1) % 5000 === 0) {
                this.logCallback(`  Progress: ${(i + 1).toLocaleString()} / ${this.iterations.toLocaleString()}`);
            }
        }
        
        const endTime = performance.now();
        const totalTime = endTime - startTime;
        
        const results = {
            protocol: 'Hybrid (X25519 + Kyber-768)',
            totalTime: { value: totalTime, unit: 'ms' },
            avgTimePerHandshake: { value: totalTime / this.iterations, unit: 'ms' },
            avgPayload1Size: { value: totalPayload1Size / this.iterations, unit: 'bytes' },
            avgPayload2Size: { value: totalPayload2Size / this.iterations, unit: 'bytes' },
            totalPayloadSize: { value: (totalPayload1Size + totalPayload2Size) / this.iterations, unit: 'bytes' },
            avgNetworkDelay: { value: totalNetworkDelay / this.iterations, unit: 'ms' },
            iterations: this.iterations
        };
        
        this.logCallback(`Completed in ${(totalTime / 1000).toFixed(2)}s`);
        this.logCallback(`  Avg time/handshake: ${results.avgTimePerHandshake.value.toFixed(4)}ms`);
        this.logCallback(`  Avg payload size: ${results.totalPayloadSize.value.toFixed(0)} bytes`);
        this.logCallback(`  Avg network delay: ${results.avgNetworkDelay.value.toFixed(4)}ms`);
        
        return results;
    }

    async hybridHandshakeOnce() {
    
        const aliceX25519 = this.nacl.box.keyPair();
        
        const aliceKyberSeed = this.nacl.randomBytes(64);
        const aliceKyberKeys = this.kyber.keygen(aliceKyberSeed);
        
        const payload1 = new Uint8Array([
            ...aliceX25519.publicKey,      
            ...aliceKyberKeys.publicKey    
        ]);
        
        const bobX25519 = this.nacl.box.keyPair();
        
        const bobX25519Shared = this.nacl.scalarMult(
            bobX25519.secretKey,
            aliceX25519.publicKey
        );
        
        const kyberEncapsulated = this.kyber.encapsulate(aliceKyberKeys.publicKey);
        
        const payload2 = new Uint8Array([
            ...bobX25519.publicKey,           // 32 bytes
            ...kyberEncapsulated.cipherText   // 1088 bytes for Kyber-768
        ]);
        
        const aliceX25519Shared = this.nacl.scalarMult(
            aliceX25519.secretKey,
            bobX25519.publicKey
        );
        
        const kyberSharedSecret = this.kyber.decapsulate(
            kyberEncapsulated.cipherText,
            aliceKyberKeys.secretKey
        );
        
        const finalSharedSecret = new Uint8Array([
            ...aliceX25519Shared,
            ...kyberSharedSecret
        ]);
        
        return {
            payload1Size: payload1.length,
            payload2Size: payload2.length,
            sharedSecret: finalSharedSecret
        };
    }

    /**2000
     * Protocol B: Pure PQC "2-KEM" (Mutual Kyber-768)
     * 
     * Setup: Alice and Bob have static Kyber public keys
     * Steps:
     * 1. Alice encapsulates secret against Bob's static public key
     * 2. Alice -> Bob: Kyber Ciphertext
     * 3. Bob encapsulates secret against Alice's static public key
     * 4. Bob -> Alice: Kyber Ciphertext
     * 5. Bob decapsulates Alice's ciphertext
     * 6. Alice decapsulates Bob's ciphertext
     * 7. Result: Combined shared secrets
     */
    async run2KEMBenchmark() {
        const networkSim = new NetworkSimulator(this.networkProfile);
        
        this.logCallback(`Warming up JIT (${this.warmupIterations} iterations)...`);
        for (let i = 0; i < this.warmupIterations; i++) {
            await this.twoKEMHandshakeOnce();
        }
        
        this.logCallback('Running benchmark...');
        const startTime = performance.now();
        
        let totalPayload1Size = 0;
        let totalPayload2Size = 0;
        let totalNetworkDelay = 0;
        
        for (let i = 0; i < this.iterations; i++) {
            const result = await this.twoKEMHandshakeOnce();
            
            const delay1 = await networkSim.simulateTransmission(result.payload1Size);
            const delay2 = await networkSim.simulateTransmission(result.payload2Size);
            
            totalPayload1Size += result.payload1Size;
            totalPayload2Size += result.payload2Size;
            totalNetworkDelay += delay1 + delay2;
            
            if ((i + 1) % 100 === 0) {
                await new Promise(resolve => setTimeout(resolve, 0));
            }
            
            if ((i + 1) % 5000 === 0) {
                this.logCallback(`  Progress: ${(i + 1).toLocaleString()} / ${this.iterations.toLocaleString()}`);
            }
        }
        
        const endTime = performance.now();
        const totalTime = endTime - startTime;
        
        const results = {
            protocol: 'Pure PQC 2-KEM (Mutual Kyber-768)',
            totalTime: { value: totalTime, unit: 'ms' },
            avgTimePerHandshake: { value: totalTime / this.iterations, unit: 'ms' },
            avgPayload1Size: { value: totalPayload1Size / this.iterations, unit: 'bytes' },
            avgPayload2Size: { value: totalPayload2Size / this.iterations, unit: 'bytes' },
            totalPayloadSize: { value: (totalPayload1Size + totalPayload2Size) / this.iterations, unit: 'bytes' },
            avgNetworkDelay: { value: totalNetworkDelay / this.iterations, unit: 'ms' },
            iterations: this.iterations
        };
        
        this.logCallback(`Completed in ${(totalTime / 1000).toFixed(2)}s`);
        this.logCallback(`  Avg time/handshake: ${results.avgTimePerHandshake.value.toFixed(4)}ms`);
        this.logCallback(`  Avg payload size: ${results.totalPayloadSize.value.toFixed(0)} bytes`);
        this.logCallback(`  Avg network delay: ${results.avgNetworkDelay.value.toFixed(4)}ms`);
        
        return results;
    }

    async twoKEMHandshakeOnce() {
        const aliceSeed = this.nacl.randomBytes(64);
        const aliceKeys = this.kyber.keygen(aliceSeed);
        
        const bobSeed = this.nacl.randomBytes(64);
        const bobKeys = this.kyber.keygen(bobSeed);
        
        const aliceToBobEncap = this.kyber.encapsulate(bobKeys.publicKey);
        

        const payload1 = aliceToBobEncap.cipherText; // 1088 bytes for Kyber-768
        
        const bobToAliceEncap = this.kyber.encapsulate(aliceKeys.publicKey);
        
        const payload2 = bobToAliceEncap.cipherText; // 1088 bytes for Kyber-768
        
        const bobDecapsulated = this.kyber.decapsulate(
            aliceToBobEncap.cipherText,
            bobKeys.secretKey
        );
        
        const aliceDecapsulated = this.kyber.decapsulate(
            bobToAliceEncap.cipherText,
            aliceKeys.secretKey
        );
        
        const combinedSecret = new Uint8Array([
            ...aliceDecapsulated,
            ...bobDecapsulated
        ]);
        
        return {
            payload1Size: payload1.length,
            payload2Size: payload2.length,
            sharedSecret: combinedSecret
        };
    }

    /**
     * Protocol C: Hybrid "2-KEM" (X25519 + Mutual Kyber-768)
     * 
     * Combines the best of both protocols:
     * - Bilateral entropy: Both parties contribute to final secret
     * - PQC security: Two Kyber-768 KEMs
     * - Backwards compatibility: X25519 for classical security
     * 
     * Steps:
     * 1. Alice generates ephemeral X25519 + Kyber keypairs
     * 2. Bob generates ephemeral X25519 + Kyber keypairs  
     * 3. Alice -> Bob: X25519 PubKey + Kyber PubKey
     * 4. Bob encapsulates against Alice's Kyber pubkey, calculates X25519 shared
     * 5. Bob -> Alice: X25519 PubKey + Kyber PubKey + Kyber Ciphertext
     * 6. Alice encapsulates against Bob's Kyber pubkey, calculates X25519 shared, decapsulates Bob's ciphertext
     * 7. Alice -> Bob: Kyber Ciphertext
     * 8. Bob decapsulates Alice's ciphertext
     * 9. Result: X25519 shared + 2x Kyber shared secrets
     * 
     * This requires 3 messages but provides bilateral PQC entropy
     */
    async runHybrid2KEMBenchmark() {
        const networkSim = new NetworkSimulator(this.networkProfile);
        
        this.logCallback(`Warming up JIT (${this.warmupIterations} iterations)...`);
        for (let i = 0; i < this.warmupIterations; i++) {
            await this.hybrid2KEMHandshakeOnce();
        }
        
        this.logCallback('Running benchmark...');
        const startTime = performance.now();
        
        let totalPayload1Size = 0;
        let totalPayload2Size = 0;
        let totalPayload3Size = 0;
        let totalNetworkDelay = 0;
        
        for (let i = 0; i < this.iterations; i++) {
            const result = await this.hybrid2KEMHandshakeOnce();
            
            const delay1 = await networkSim.simulateTransmission(result.payload1Size);
            const delay2 = await networkSim.simulateTransmission(result.payload2Size);
            const delay3 = await networkSim.simulateTransmission(result.payload3Size);
            
            totalPayload1Size += result.payload1Size;
            totalPayload2Size += result.payload2Size;
            totalPayload3Size += result.payload3Size;
            totalNetworkDelay += delay1 + delay2 + delay3;
            
            if ((i + 1) % 100 === 0) {
                await new Promise(resolve => setTimeout(resolve, 0));
            }
            
            if ((i + 1) % 5000 === 0) {
                this.logCallback(`  Progress: ${(i + 1).toLocaleString()} / ${this.iterations.toLocaleString()}`);
            }
        }
        
        const endTime = performance.now();
        const totalTime = endTime - startTime;
        
        const results = {
            protocol: 'Hybrid 2-KEM (X25519 + Mutual Kyber-768)',
            totalTime: { value: totalTime, unit: 'ms' },
            avgTimePerHandshake: { value: totalTime / this.iterations, unit: 'ms' },
            avgPayload1Size: { value: totalPayload1Size / this.iterations, unit: 'bytes' },
            avgPayload2Size: { value: totalPayload2Size / this.iterations, unit: 'bytes' },
            avgPayload3Size: { value: totalPayload3Size / this.iterations, unit: 'bytes' },
            totalPayloadSize: { value: (totalPayload1Size + totalPayload2Size + totalPayload3Size) / this.iterations, unit: 'bytes' },
            avgNetworkDelay: { value: totalNetworkDelay / this.iterations, unit: 'ms' },
            iterations: this.iterations
        };
        
        this.logCallback(`Completed in ${(totalTime / 1000).toFixed(2)}s`);
        this.logCallback(`  Avg time/handshake: ${results.avgTimePerHandshake.value.toFixed(4)}ms`);
        this.logCallback(`  Avg payload size: ${results.totalPayloadSize.value.toFixed(0)} bytes`);
        this.logCallback(`  Avg network delay: ${results.avgNetworkDelay.value.toFixed(4)}ms`);
        
        return results;
    }

    async hybrid2KEMHandshakeOnce() {
        // 1.
        const aliceX25519 = this.nacl.box.keyPair();
        const aliceSeed = this.nacl.randomBytes(64);
        const aliceKyberKeys = this.kyber.keygen(aliceSeed);
        
        // 2. 
        const bobX25519 = this.nacl.box.keyPair();
        const bobSeed = this.nacl.randomBytes(64);
        const bobKyberKeys = this.kyber.keygen(bobSeed);
        
        // 3. 
        const payload1 = new Uint8Array([
            ...aliceX25519.publicKey,      // 32 bytes
            ...aliceKyberKeys.publicKey    // 1184 bytes for Kyber-768
        ]);
        
        // 4. 
        const bobToAliceEncap = this.kyber.encapsulate(aliceKyberKeys.publicKey);
        const bobX25519Shared = this.nacl.scalarMult(
            bobX25519.secretKey,
            aliceX25519.publicKey
        );
        
        // 5. 
        const payload2 = new Uint8Array([
            ...bobX25519.publicKey,           // 32 bytes
            ...bobKyberKeys.publicKey,        // 1184 bytes
            ...bobToAliceEncap.cipherText     // 1088 bytes
        ]);
        
        // 6. 
        const aliceToBobEncap = this.kyber.encapsulate(bobKyberKeys.publicKey);
        const aliceX25519Shared = this.nacl.scalarMult(
            aliceX25519.secretKey,
            bobX25519.publicKey
        );
        const aliceKyberShared = this.kyber.decapsulate(
            bobToAliceEncap.cipherText,
            aliceKyberKeys.secretKey
        );
        
        // 7. 
        const payload3 = aliceToBobEncap.cipherText; // 1088 bytes
        
        // 8. 
        const bobKyberShared = this.kyber.decapsulate(
            aliceToBobEncap.cipherText,
            bobKyberKeys.secretKey
        );
        
        // 9. 
        const finalSharedSecret = new Uint8Array([
            ...aliceX25519Shared,
            ...aliceKyberShared,
            ...bobKyberShared
        ]);
        
        return {
            payload1Size: payload1.length,
            payload2Size: payload2.length,
            payload3Size: payload3.length,
            sharedSecret: finalSharedSecret
        };
    }

    displayComparison() {
        this.logCallback('\n╔═══════════════════════════════════════════════════════════════════╗');
        this.logCallback('║           PQC HANDSHAKE BENCHMARK COMPARISON                      ║');
        this.logCallback('╚═══════════════════════════════════════════════════════════════════╝');
        this.logCallback('');
        
        const ecdh = this.results.ecdh;
        const hybrid = this.results.hybrid;
        const twoKEM = this.results.twoKEM;
        const hybrid2KEM = this.results.hybrid2KEM;
        
        this.logCallback('TIME COMPLEXITY (Latency)');
        this.logCallback('─────────────────────────────────────────────────────────────────');
        this.logCallback(`  Pure ECDH (X25519):              ${ecdh.avgTimePerHandshake.value.toFixed(4)}ms per handshake`);
        this.logCallback(`  Hybrid (X25519 + Kyber):         ${hybrid.avgTimePerHandshake.value.toFixed(4)}ms per handshake`);
        this.logCallback(`  Pure PQC 2-KEM:                  ${twoKEM.avgTimePerHandshake.value.toFixed(4)}ms per handshake`);
        this.logCallback(`  Hybrid 2-KEM (X25519 + 2xKyber): ${hybrid2KEM.avgTimePerHandshake.value.toFixed(4)}ms per handshake`);
        
        const fastest = Math.min(ecdh.avgTimePerHandshake.value, hybrid.avgTimePerHandshake.value, twoKEM.avgTimePerHandshake.value, hybrid2KEM.avgTimePerHandshake.value);
        this.logCallback(`  Fastest: ${fastest === ecdh.avgTimePerHandshake.value ? 'ECDH' : fastest === hybrid.avgTimePerHandshake.value ? 'Hybrid' : fastest === twoKEM.avgTimePerHandshake.value ? '2-KEM' : 'Hybrid 2-KEM'}`);
        this.logCallback('');
        
        this.logCallback('SPACE COMPLEXITY (Bandwidth)');
        this.logCallback('─────────────────────────────────────────────────────────────────');
        this.logCallback(`  Pure ECDH (X25519):`);
        this.logCallback(`    Payload 1 (Alice->Bob):  ${ecdh.avgPayload1Size.value.toFixed(0)} bytes`);
        this.logCallback(`    Payload 2 (Bob->Alice):  ${ecdh.avgPayload2Size.value.toFixed(0)} bytes`);
        this.logCallback(`    Total (2 messages):      ${ecdh.totalPayloadSize.value.toFixed(0)} bytes`);
        this.logCallback('');
        this.logCallback(`  Hybrid (X25519 + Kyber):`);
        this.logCallback(`    Payload 1 (Alice->Bob):  ${hybrid.avgPayload1Size.value.toFixed(0)} bytes`);
        this.logCallback(`    Payload 2 (Bob->Alice):  ${hybrid.avgPayload2Size.value.toFixed(0)} bytes`);
        this.logCallback(`    Total (2 messages):      ${hybrid.totalPayloadSize.value.toFixed(0)} bytes`);
        this.logCallback('');
        this.logCallback(`  Pure PQC 2-KEM:`);
        this.logCallback(`    Payload 1 (Alice->Bob):  ${twoKEM.avgPayload1Size.value.toFixed(0)} bytes`);
        this.logCallback(`    Payload 2 (Bob->Alice):  ${twoKEM.avgPayload2Size.value.toFixed(0)} bytes`);
        this.logCallback(`    Total (2 messages):      ${twoKEM.totalPayloadSize.value.toFixed(0)} bytes`);
        this.logCallback('');
        this.logCallback(`  Hybrid 2-KEM (X25519 + 2xKyber):`);
        this.logCallback(`    Payload 1 (Alice->Bob):  ${hybrid2KEM.avgPayload1Size.value.toFixed(0)} bytes`);
        this.logCallback(`    Payload 2 (Bob->Alice):  ${hybrid2KEM.avgPayload2Size.value.toFixed(0)} bytes`);
        this.logCallback(`    Payload 3 (Alice->Bob):  ${hybrid2KEM.avgPayload3Size.value.toFixed(0)} bytes`);
        this.logCallback(`    Total (3 messages):      ${hybrid2KEM.totalPayloadSize.value.toFixed(0)} bytes`);
        this.logCallback('');
        
        const smallest = Math.min(ecdh.totalPayloadSize.value, hybrid.totalPayloadSize.value, twoKEM.totalPayloadSize.value, hybrid2KEM.totalPayloadSize.value);
        this.logCallback(`  Most efficient: ${smallest === ecdh.totalPayloadSize.value ? 'ECDH' : smallest === hybrid.totalPayloadSize.value ? 'Hybrid' : smallest === twoKEM.totalPayloadSize.value ? '2-KEM' : 'Hybrid 2-KEM'} (${smallest.toFixed(0)} bytes)`);
        this.logCallback('');
        
        if (this.networkProfile.latency > 0 || this.networkProfile.bandwidth < Infinity) {
            this.logCallback('NETWORK IMPACT');
            this.logCallback('─────────────────────────────────────────────────────────────────');
            this.logCallback(`  Profile: ${this.networkProfile.name}`);
            this.logCallback(`  ECDH avg network delay:      ${ecdh.avgNetworkDelay.value.toFixed(4)}ms`);
            this.logCallback(`  Hybrid avg network delay:    ${hybrid.avgNetworkDelay.value.toFixed(4)}ms`);
            this.logCallback(`  2-KEM avg network delay:     ${twoKEM.avgNetworkDelay.value.toFixed(4)}ms`);
            this.logCallback(`  Hybrid 2-KEM network delay:  ${hybrid2KEM.avgNetworkDelay.value.toFixed(4)}ms`);
            
            const lowestNetworkDelay = Math.min(ecdh.avgNetworkDelay.value, hybrid.avgNetworkDelay.value, twoKEM.avgNetworkDelay.value, hybrid2KEM.avgNetworkDelay.value);
            this.logCallback(`  Lowest network delay: ${lowestNetworkDelay === ecdh.avgNetworkDelay.value ? 'ECDH' : lowestNetworkDelay === hybrid.avgNetworkDelay.value ? 'Hybrid' : lowestNetworkDelay === twoKEM.avgNetworkDelay.value ? '2-KEM' : 'Hybrid 2-KEM'}`);
            this.logCallback('');
        }
        
        const ecdhTotal = ecdh.avgTimePerHandshake.value + ecdh.avgNetworkDelay.value;
        const hybridTotal = hybrid.avgTimePerHandshake.value + hybrid.avgNetworkDelay.value;
        const twoKEMTotal = twoKEM.avgTimePerHandshake.value + twoKEM.avgNetworkDelay.value;
        const hybrid2KEMTotal = hybrid2KEM.avgTimePerHandshake.value + hybrid2KEM.avgNetworkDelay.value;
        
        this.logCallback('TOTAL TIME (Computation + Network)');
        this.logCallback('─────────────────────────────────────────────────────────────────');
        this.logCallback(`  ECDH:            ${ecdhTotal.toFixed(4)}ms`);
        this.logCallback(`  Hybrid:          ${hybridTotal.toFixed(4)}ms`);
        this.logCallback(`  2-KEM:           ${twoKEMTotal.toFixed(4)}ms`);
        this.logCallback(`  Hybrid 2-KEM:    ${hybrid2KEMTotal.toFixed(4)}ms`);
        
        const fastestTotal = Math.min(ecdhTotal, hybridTotal, twoKEMTotal, hybrid2KEMTotal);
        this.logCallback(`  Winner: ${fastestTotal === ecdhTotal ? 'ECDH' : fastestTotal === hybridTotal ? 'Hybrid' : fastestTotal === twoKEMTotal ? '2-KEM' : 'Hybrid 2-KEM'} (${fastestTotal.toFixed(4)}ms)`);
        this.logCallback('');
    }

    exportResults() {
        return {
            metadata: {
                iterations: this.iterations,
                warmupIterations: this.warmupIterations,
                networkProfile: {
                    name: this.networkProfile.name,
                    latency: this.networkProfile.latency,
                    bandwidth: this.networkProfile.bandwidth,
                    jitter: this.networkProfile.jitter
                },
                timestamp: new Date().toISOString()
            },
            results: {
                ecdh: this.results.ecdh,
                hybrid: this.results.hybrid,
                twoKEM: this.results.twoKEM,
                hybrid2KEM: this.results.hybrid2KEM
            }
        };
    }
}
