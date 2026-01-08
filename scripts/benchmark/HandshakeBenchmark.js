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
            hybrid: null,
            twoKEM: null
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
        
        this.logCallback('--- Protocol A: Hybrid Handshake (X25519 + Kyber-768) ---');
        this.results.hybrid = await this.runHybridBenchmark();
        
        this.logCallback('');
        
        this.logCallback('--- Protocol B: Pure PQC "2-KEM" (Mutual Kyber-768) ---');
        this.results.twoKEM = await this.run2KEMBenchmark();
        
        this.logCallback('');
        
        this.displayComparison();
        
        return this.results;
    }

    /**
     * Protocol A: Hybrid Handshake (X25519 + Kyber-768)
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

    /**
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

    displayComparison() {
        this.logCallback('\n╔═══════════════════════════════════════════════════════════════════╗');
        this.logCallback('║           PQC HANDSHAKE BENCHMARK COMPARISON                      ║');
        this.logCallback('╚═══════════════════════════════════════════════════════════════════╝');
        this.logCallback('');
        
        const hybrid = this.results.hybrid;
        const twoKEM = this.results.twoKEM;
        
        this.logCallback('TIME COMPLEXITY (Latency)');
        this.logCallback('─────────────────────────────────────────────────────────────────');
        this.logCallback(`  Hybrid (X25519 + Kyber):  ${hybrid.avgTimePerHandshake.value.toFixed(4)}ms per handshake`);
        this.logCallback(`  Pure PQC 2-KEM:           ${twoKEM.avgTimePerHandshake.value.toFixed(4)}ms per handshake`);
        
        const timeDiff = ((twoKEM.avgTimePerHandshake.value - hybrid.avgTimePerHandshake.value) / hybrid.avgTimePerHandshake.value * 100);
        const timeWinner = timeDiff > 0 ? 'Hybrid is faster' : '2-KEM is faster';
        this.logCallback(`  Difference:               ${Math.abs(timeDiff).toFixed(2)}% (${timeWinner})`);
        this.logCallback('');
        
        this.logCallback('SPACE COMPLEXITY (Bandwidth)');
        this.logCallback('─────────────────────────────────────────────────────────────────');
        this.logCallback(`  Hybrid (X25519 + Kyber):`);
        this.logCallback(`    Payload 1 (Alice->Bob):  ${hybrid.avgPayload1Size.value.toFixed(0)} bytes`);
        this.logCallback(`    Payload 2 (Bob->Alice):  ${hybrid.avgPayload2Size.value.toFixed(0)} bytes`);
        this.logCallback(`    Total:                   ${hybrid.totalPayloadSize.value.toFixed(0)} bytes`);
        this.logCallback('');
        this.logCallback(`  Pure PQC 2-KEM:`);
        this.logCallback(`    Payload 1 (Alice->Bob):  ${twoKEM.avgPayload1Size.value.toFixed(0)} bytes`);
        this.logCallback(`    Payload 2 (Bob->Alice):  ${twoKEM.avgPayload2Size.value.toFixed(0)} bytes`);
        this.logCallback(`    Total:                   ${twoKEM.totalPayloadSize.value.toFixed(0)} bytes`);
        this.logCallback('');
        
        const sizeDiff = twoKEM.totalPayloadSize.value - hybrid.totalPayloadSize.value;
        const sizeDiffPct = (sizeDiff / hybrid.totalPayloadSize.value * 100);
        this.logCallback(`  Difference:               ${sizeDiff.toFixed(0)} bytes (${sizeDiffPct.toFixed(2)}% more for 2-KEM)`);
        this.logCallback('');
        
        let networkDiff = 0;
        if (this.networkProfile.latency > 0 || this.networkProfile.bandwidth < Infinity) {
            this.logCallback('NETWORK IMPACT');
            this.logCallback('─────────────────────────────────────────────────────────────────');
            this.logCallback(`  Profile: ${this.networkProfile.name}`);
            this.logCallback(`  Hybrid avg network delay:  ${hybrid.avgNetworkDelay.value.toFixed(4)}ms`);
            this.logCallback(`  2-KEM avg network delay:   ${twoKEM.avgNetworkDelay.value.toFixed(4)}ms`);
            
            networkDiff = twoKEM.avgNetworkDelay.value - hybrid.avgNetworkDelay.value;
            this.logCallback(`  Impact of extra payload:   +${networkDiff.toFixed(4)}ms (${((networkDiff / hybrid.avgNetworkDelay.value) * 100).toFixed(2)}%)`);
            this.logCallback('');
        }
        
        const hybridTotal = hybrid.avgTimePerHandshake.value + hybrid.avgNetworkDelay.value;
        const twoKEMTotal = twoKEM.avgTimePerHandshake.value + twoKEM.avgNetworkDelay.value;
        
        this.logCallback('TOTAL TIME (Computation + Network)');
        this.logCallback('─────────────────────────────────────────────────────────────────');
        this.logCallback(`  Hybrid:  ${hybridTotal.toFixed(4)}ms`);
        this.logCallback(`  2-KEM:   ${twoKEMTotal.toFixed(4)}ms`);
        this.logCallback('');
        
        this.logCallback('CONCLUSION');
        this.logCallback('─────────────────────────────────────────────────────────────────');
        
        if (this.networkProfile.name === 'High-Speed / Local') {
            this.logCallback('  On high-speed networks, computation dominates.');
            if (timeDiff > 5) {
                this.logCallback('  → Hybrid handshake is significantly faster due to X25519 efficiency.');
            } else {
                this.logCallback('  → Both protocols perform similarly; bandwidth overhead is negligible.');
            }
        } else {
            this.logCallback('  On constrained networks (mobile/4G), payload size matters.');
            if (networkDiff > 5) {
                this.logCallback(`  → 2-KEM suffers from ${sizeDiff.toFixed(0)} extra bytes, adding ${networkDiff.toFixed(2)}ms delay.`);
                this.logCallback('  → Hybrid approach is more efficient in real-world scenarios.');
            } else {
                this.logCallback('  → Network latency dominates; computational differences are minimal.');
            }
        }
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
                hybrid: this.results.hybrid,
                twoKEM: this.results.twoKEM
            }
        };
    }
}
