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

    /**
     * Compute descriptive statistics from an array of per-iteration timings.
     * @param {number[]} times - Array of per-handshake durations in ms
     * @returns {Object} - min, max, mean, median, p95, p99, stddev, cv, throughput
     */
    computeStats(times) {
        const n = times.length;
        if (n === 0) return {};

        const sorted = times.slice().sort((a, b) => a - b);
        const sum = times.reduce((acc, v) => acc + v, 0);
        const mean = sum / n;

        const variance = times.reduce((acc, v) => acc + (v - mean) ** 2, 0) / n;
        const stddev = Math.sqrt(variance);
        const cv = mean > 0 ? (stddev / mean) * 100 : 0; // coefficient of variation %

        const percentile = (p) => {
            const idx = (p / 100) * (n - 1);
            const lo = Math.floor(idx);
            const hi = Math.ceil(idx);
            return lo === hi ? sorted[lo] : sorted[lo] + (sorted[hi] - sorted[lo]) * (idx - lo);
        };

        return {
            min:        { value: sorted[0],        unit: 'ms' },
            max:        { value: sorted[n - 1],    unit: 'ms' },
            median:     { value: percentile(50),   unit: 'ms' },
            p95:        { value: percentile(95),   unit: 'ms' },
            p99:        { value: percentile(99),   unit: 'ms' },
            stddev:     { value: stddev,            unit: 'ms' },
            cv:         { value: cv,                unit: '%'  },
            throughput: { value: mean > 0 ? 1000 / mean : 0, unit: 'handshakes/s' }
        };
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
        const iterationTimes = [];
        const phaseKeygen = [];
        const phaseScalarMult = [];

        for (let i = 0; i < this.iterations; i++) {
            const t0 = performance.now();
            const result = await this.ecdhHandshakeOnce();
            const t1 = performance.now();

            iterationTimes.push(t1 - t0);
            phaseKeygen.push(result.phases.keygen);
            phaseScalarMult.push(result.phases.scalarMult);

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
        const stats = this.computeStats(iterationTimes);

        const results = {
            protocol: 'Pure ECDH (X25519)',
            messageCount: 2,
            totalTime: { value: totalTime, unit: 'ms' },
            avgTimePerHandshake: { value: totalTime / this.iterations, unit: 'ms' },
            avgPayload1Size: { value: totalPayload1Size / this.iterations, unit: 'bytes' },
            avgPayload2Size: { value: totalPayload2Size / this.iterations, unit: 'bytes' },
            totalPayloadSize: { value: (totalPayload1Size + totalPayload2Size) / this.iterations, unit: 'bytes' },
            avgNetworkDelay: { value: totalNetworkDelay / this.iterations, unit: 'ms' },
            iterations: this.iterations,
            stats,
            phases: {
                keygen:     this.computeStats(phaseKeygen),
                scalarMult: this.computeStats(phaseScalarMult)
            },
            // Security bits / total payload bytes  (X25519 ≈ 128 classical bits)
            securityEfficiency: { value: 128 / ((totalPayload1Size + totalPayload2Size) / this.iterations), unit: 'bits/byte' }
        };

        this.logCallback(`Completed in ${(totalTime / 1000).toFixed(2)}s`);
        this.logCallback(`  Avg time/handshake: ${results.avgTimePerHandshake.value.toFixed(4)}ms  (p95: ${stats.p95.value.toFixed(4)}ms, p99: ${stats.p99.value.toFixed(4)}ms)`);
        this.logCallback(`  Throughput: ${stats.throughput.value.toFixed(1)} handshakes/s`);
        this.logCallback(`  Stddev: ${stats.stddev.value.toFixed(4)}ms  CV: ${stats.cv.value.toFixed(2)}%`);
        this.logCallback(`  Avg payload size: ${results.totalPayloadSize.value.toFixed(0)} bytes`);
        this.logCallback(`  Avg network delay: ${results.avgNetworkDelay.value.toFixed(4)}ms`);

        return results;
    }

    async ecdhHandshakeOnce() {
        const t0 = performance.now();
        const aliceX25519 = this.nacl.box.keyPair();
        const bobX25519 = this.nacl.box.keyPair();
        const t1 = performance.now();

        const payload1 = aliceX25519.publicKey; // 32 bytes

        const t2 = performance.now();
        const bobSharedSecret = this.nacl.scalarMult(
            bobX25519.secretKey,
            aliceX25519.publicKey
        );
        const payload2 = bobX25519.publicKey; // 32 bytes
        const aliceSharedSecret = this.nacl.scalarMult(
            aliceX25519.secretKey,
            bobX25519.publicKey
        );
        const t3 = performance.now();

        return {
            payload1Size: payload1.length,
            payload2Size: payload2.length,
            sharedSecret: aliceSharedSecret,
            phases: {
                keygen:     t1 - t0,
                scalarMult: t3 - t2
            }
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
        const iterationTimes = [];
        const phaseKeygen = [];
        const phaseEncap = [];
        const phaseDecap = [];

        for (let i = 0; i < this.iterations; i++) {
            const t0 = performance.now();
            const result = await this.hybridHandshakeOnce();
            const t1 = performance.now();

            iterationTimes.push(t1 - t0);
            phaseKeygen.push(result.phases.keygen);
            phaseEncap.push(result.phases.encap);
            phaseDecap.push(result.phases.decap);

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
        const stats = this.computeStats(iterationTimes);

        const results = {
            protocol: 'Hybrid (X25519 + Kyber-768)',
            messageCount: 2,
            totalTime: { value: totalTime, unit: 'ms' },
            avgTimePerHandshake: { value: totalTime / this.iterations, unit: 'ms' },
            avgPayload1Size: { value: totalPayload1Size / this.iterations, unit: 'bytes' },
            avgPayload2Size: { value: totalPayload2Size / this.iterations, unit: 'bytes' },
            totalPayloadSize: { value: (totalPayload1Size + totalPayload2Size) / this.iterations, unit: 'bytes' },
            avgNetworkDelay: { value: totalNetworkDelay / this.iterations, unit: 'ms' },
            iterations: this.iterations,
            stats,
            phases: {
                keygen: this.computeStats(phaseKeygen),
                encap:  this.computeStats(phaseEncap),
                decap:  this.computeStats(phaseDecap)
            },
            // X25519 ≈ 128 classical bits + Kyber-768 ≈ 178 post-quantum bits → NIST level 3
            securityEfficiency: { value: 178 / ((totalPayload1Size + totalPayload2Size) / this.iterations), unit: 'bits/byte' }
        };

        this.logCallback(`Completed in ${(totalTime / 1000).toFixed(2)}s`);
        this.logCallback(`  Avg time/handshake: ${results.avgTimePerHandshake.value.toFixed(4)}ms  (p95: ${stats.p95.value.toFixed(4)}ms, p99: ${stats.p99.value.toFixed(4)}ms)`);
        this.logCallback(`  Throughput: ${stats.throughput.value.toFixed(1)} handshakes/s`);
        this.logCallback(`  Stddev: ${stats.stddev.value.toFixed(4)}ms  CV: ${stats.cv.value.toFixed(2)}%`);
        this.logCallback(`  Avg payload size: ${results.totalPayloadSize.value.toFixed(0)} bytes`);
        this.logCallback(`  Avg network delay: ${results.avgNetworkDelay.value.toFixed(4)}ms`);

        return results;
    }

    async hybridHandshakeOnce() {
        const t0 = performance.now();
        const aliceX25519 = this.nacl.box.keyPair();
        const aliceKyberSeed = this.nacl.randomBytes(64);
        const aliceKyberKeys = this.kyber.keygen(aliceKyberSeed);
        const bobX25519 = this.nacl.box.keyPair();
        const t1 = performance.now();

        const payload1 = new Uint8Array([
            ...aliceX25519.publicKey,
            ...aliceKyberKeys.publicKey
        ]);

        const t2 = performance.now();
        const bobX25519Shared = this.nacl.scalarMult(
            bobX25519.secretKey,
            aliceX25519.publicKey
        );
        const kyberEncapsulated = this.kyber.encapsulate(aliceKyberKeys.publicKey);
        const t3 = performance.now();

        const payload2 = new Uint8Array([
            ...bobX25519.publicKey,           // 32 bytes
            ...kyberEncapsulated.cipherText   // 1088 bytes for Kyber-768
        ]);

        const t4 = performance.now();
        const aliceX25519Shared = this.nacl.scalarMult(
            aliceX25519.secretKey,
            bobX25519.publicKey
        );
        const kyberSharedSecret = this.kyber.decapsulate(
            kyberEncapsulated.cipherText,
            aliceKyberKeys.secretKey
        );
        const t5 = performance.now();

        const finalSharedSecret = new Uint8Array([
            ...aliceX25519Shared,
            ...kyberSharedSecret
        ]);

        return {
            payload1Size: payload1.length,
            payload2Size: payload2.length,
            sharedSecret: finalSharedSecret,
            phases: {
                keygen: t1 - t0,
                encap:  t3 - t2,
                decap:  t5 - t4
            }
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
        const iterationTimes = [];
        const phaseKeygen = [];
        const phaseEncap = [];
        const phaseDecap = [];

        for (let i = 0; i < this.iterations; i++) {
            const t0 = performance.now();
            const result = await this.twoKEMHandshakeOnce();
            const t1 = performance.now();

            iterationTimes.push(t1 - t0);
            phaseKeygen.push(result.phases.keygen);
            phaseEncap.push(result.phases.encap);
            phaseDecap.push(result.phases.decap);

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
        const stats = this.computeStats(iterationTimes);

        const results = {
            protocol: 'Pure PQC 2-KEM (Mutual Kyber-768)',
            messageCount: 2,
            totalTime: { value: totalTime, unit: 'ms' },
            avgTimePerHandshake: { value: totalTime / this.iterations, unit: 'ms' },
            avgPayload1Size: { value: totalPayload1Size / this.iterations, unit: 'bytes' },
            avgPayload2Size: { value: totalPayload2Size / this.iterations, unit: 'bytes' },
            totalPayloadSize: { value: (totalPayload1Size + totalPayload2Size) / this.iterations, unit: 'bytes' },
            avgNetworkDelay: { value: totalNetworkDelay / this.iterations, unit: 'ms' },
            iterations: this.iterations,
            stats,
            phases: {
                keygen: this.computeStats(phaseKeygen),
                encap:  this.computeStats(phaseEncap),
                decap:  this.computeStats(phaseDecap)
            },
            // Kyber-768 ≈ 178 post-quantum bits (NIST level 3)
            securityEfficiency: { value: 178 / ((totalPayload1Size + totalPayload2Size) / this.iterations), unit: 'bits/byte' }
        };

        this.logCallback(`Completed in ${(totalTime / 1000).toFixed(2)}s`);
        this.logCallback(`  Avg time/handshake: ${results.avgTimePerHandshake.value.toFixed(4)}ms  (p95: ${stats.p95.value.toFixed(4)}ms, p99: ${stats.p99.value.toFixed(4)}ms)`);
        this.logCallback(`  Throughput: ${stats.throughput.value.toFixed(1)} handshakes/s`);
        this.logCallback(`  Stddev: ${stats.stddev.value.toFixed(4)}ms  CV: ${stats.cv.value.toFixed(2)}%`);
        this.logCallback(`  Avg payload size: ${results.totalPayloadSize.value.toFixed(0)} bytes`);
        this.logCallback(`  Avg network delay: ${results.avgNetworkDelay.value.toFixed(4)}ms`);

        return results;
    }

    async twoKEMHandshakeOnce() {
        const t0 = performance.now();
        const aliceSeed = this.nacl.randomBytes(64);
        const aliceKeys = this.kyber.keygen(aliceSeed);
        const bobSeed = this.nacl.randomBytes(64);
        const bobKeys = this.kyber.keygen(bobSeed);
        const t1 = performance.now();

        const t2 = performance.now();
        const aliceToBobEncap = this.kyber.encapsulate(bobKeys.publicKey);
        const bobToAliceEncap = this.kyber.encapsulate(aliceKeys.publicKey);
        const t3 = performance.now();

        const payload1 = aliceToBobEncap.cipherText; // 1088 bytes for Kyber-768
        const payload2 = bobToAliceEncap.cipherText; // 1088 bytes for Kyber-768

        const t4 = performance.now();
        const bobDecapsulated = this.kyber.decapsulate(
            aliceToBobEncap.cipherText,
            bobKeys.secretKey
        );
        const aliceDecapsulated = this.kyber.decapsulate(
            bobToAliceEncap.cipherText,
            aliceKeys.secretKey
        );
        const t5 = performance.now();

        const combinedSecret = new Uint8Array([
            ...aliceDecapsulated,
            ...bobDecapsulated
        ]);

        return {
            payload1Size: payload1.length,
            payload2Size: payload2.length,
            sharedSecret: combinedSecret,
            phases: {
                keygen: t1 - t0,
                encap:  t3 - t2,
                decap:  t5 - t4
            }
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
        const iterationTimes = [];
        const phaseKeygen = [];
        const phaseEncap = [];
        const phaseDecap = [];

        for (let i = 0; i < this.iterations; i++) {
            const t0 = performance.now();
            const result = await this.hybrid2KEMHandshakeOnce();
            const t1 = performance.now();

            iterationTimes.push(t1 - t0);
            phaseKeygen.push(result.phases.keygen);
            phaseEncap.push(result.phases.encap);
            phaseDecap.push(result.phases.decap);

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
        const stats = this.computeStats(iterationTimes);

        const results = {
            protocol: 'Hybrid 2-KEM (X25519 + Mutual Kyber-768)',
            messageCount: 3,
            totalTime: { value: totalTime, unit: 'ms' },
            avgTimePerHandshake: { value: totalTime / this.iterations, unit: 'ms' },
            avgPayload1Size: { value: totalPayload1Size / this.iterations, unit: 'bytes' },
            avgPayload2Size: { value: totalPayload2Size / this.iterations, unit: 'bytes' },
            avgPayload3Size: { value: totalPayload3Size / this.iterations, unit: 'bytes' },
            totalPayloadSize: { value: (totalPayload1Size + totalPayload2Size + totalPayload3Size) / this.iterations, unit: 'bytes' },
            avgNetworkDelay: { value: totalNetworkDelay / this.iterations, unit: 'ms' },
            iterations: this.iterations,
            stats,
            phases: {
                keygen: this.computeStats(phaseKeygen),
                encap:  this.computeStats(phaseEncap),
                decap:  this.computeStats(phaseDecap)
            },
            // X25519 + 2x Kyber-768: 178 PQC bits (dominant)
            securityEfficiency: { value: 178 / ((totalPayload1Size + totalPayload2Size + totalPayload3Size) / this.iterations), unit: 'bits/byte' }
        };

        this.logCallback(`Completed in ${(totalTime / 1000).toFixed(2)}s`);
        this.logCallback(`  Avg time/handshake: ${results.avgTimePerHandshake.value.toFixed(4)}ms  (p95: ${stats.p95.value.toFixed(4)}ms, p99: ${stats.p99.value.toFixed(4)}ms)`);
        this.logCallback(`  Throughput: ${stats.throughput.value.toFixed(1)} handshakes/s`);
        this.logCallback(`  Stddev: ${stats.stddev.value.toFixed(4)}ms  CV: ${stats.cv.value.toFixed(2)}%`);
        this.logCallback(`  Avg payload size: ${results.totalPayloadSize.value.toFixed(0)} bytes`);
        this.logCallback(`  Avg network delay: ${results.avgNetworkDelay.value.toFixed(4)}ms`);

        return results;
    }

    async hybrid2KEMHandshakeOnce() {
        // 1. & 2. Keygen phase
        const t0 = performance.now();
        const aliceX25519 = this.nacl.box.keyPair();
        const aliceSeed = this.nacl.randomBytes(64);
        const aliceKyberKeys = this.kyber.keygen(aliceSeed);
        const bobX25519 = this.nacl.box.keyPair();
        const bobSeed = this.nacl.randomBytes(64);
        const bobKyberKeys = this.kyber.keygen(bobSeed);
        const t1 = performance.now();

        // 3.
        const payload1 = new Uint8Array([
            ...aliceX25519.publicKey,      // 32 bytes
            ...aliceKyberKeys.publicKey    // 1184 bytes for Kyber-768
        ]);

        // 4. Encapsulation phase
        const t2 = performance.now();
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

        const aliceToBobEncap = this.kyber.encapsulate(bobKyberKeys.publicKey);
        const aliceX25519Shared = this.nacl.scalarMult(
            aliceX25519.secretKey,
            bobX25519.publicKey
        );
        const t3 = performance.now();

        // 6. & 8. Decapsulation phase
        const t4 = performance.now();
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
        const t5 = performance.now();

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
            sharedSecret: finalSharedSecret,
            phases: {
                keygen: t1 - t0,
                encap:  t3 - t2,
                decap:  t5 - t4
            }
        };
    }

    displayComparison() {
        this.logCallback('\n╔═══════════════════════════════════════════════════════════════════╗');
        this.logCallback('║           PQC HANDSHAKE BENCHMARK COMPARISON                      ║');
        this.logCallback('╚═══════════════════════════════════════════════════════════════════╝');
        this.logCallback('');

        const ecdh     = this.results.ecdh;
        const hybrid   = this.results.hybrid;
        const twoKEM   = this.results.twoKEM;
        const hybrid2KEM = this.results.hybrid2KEM;

        const label = (r) => {
            if (r === ecdh) return 'ECDH';
            if (r === hybrid) return 'Hybrid';
            if (r === twoKEM) return '2-KEM';
            return 'Hybrid 2-KEM';
        };

        // ── TIME COMPLEXITY ──────────────────────────────────────────────
        this.logCallback('TIME COMPLEXITY (Latency)  — avg / median / p95 / p99');
        this.logCallback('─────────────────────────────────────────────────────────────────');
        for (const r of [ecdh, hybrid, twoKEM, hybrid2KEM]) {
            const s = r.stats;
            this.logCallback(`  ${r.protocol}`);
            this.logCallback(`    avg: ${r.avgTimePerHandshake.value.toFixed(4)}ms  median: ${s.median.value.toFixed(4)}ms  p95: ${s.p95.value.toFixed(4)}ms  p99: ${s.p99.value.toFixed(4)}ms`);
            this.logCallback(`    min: ${s.min.value.toFixed(4)}ms  max: ${s.max.value.toFixed(4)}ms  σ: ${s.stddev.value.toFixed(4)}ms  CV: ${s.cv.value.toFixed(2)}%`);
            this.logCallback(`    throughput: ${s.throughput.value.toFixed(1)} handshakes/s  (${r.messageCount} message${r.messageCount > 1 ? 's' : ''})`);
        }
        const allAvg = [ecdh, hybrid, twoKEM, hybrid2KEM].map(r => r.avgTimePerHandshake.value);
        const fastestAvg = Math.min(...allAvg);
        const fastestR = [ecdh, hybrid, twoKEM, hybrid2KEM][allAvg.indexOf(fastestAvg)];
        this.logCallback(`  Fastest: ${label(fastestR)} (${fastestAvg.toFixed(4)}ms avg)`);
        this.logCallback('');

        // ── PHASE BREAKDOWN ──────────────────────────────────────────────
        this.logCallback('PHASE BREAKDOWN (avg time per operation)');
        this.logCallback('─────────────────────────────────────────────────────────────────');
        for (const r of [ecdh, hybrid, twoKEM, hybrid2KEM]) {
            this.logCallback(`  ${r.protocol}`);
            if (r.phases.keygen)     this.logCallback(`    keygen:     ${r.phases.keygen.throughput     ? (1000/r.phases.keygen.throughput.value).toFixed(4) : r.phases.keygen.median?.value.toFixed(4)}ms avg  (${r.phases.keygen.throughput?.value.toFixed(0)} ops/s)`);
            if (r.phases.encap)      this.logCallback(`    encapsulate:${r.phases.encap.throughput      ? ' ' + (1000/r.phases.encap.throughput.value).toFixed(4) : ' ' + r.phases.encap.median?.value.toFixed(4)}ms avg  (${r.phases.encap.throughput?.value.toFixed(0)} ops/s)`);
            if (r.phases.decap)      this.logCallback(`    decapsulate:${r.phases.decap.throughput      ? ' ' + (1000/r.phases.decap.throughput.value).toFixed(4) : ' ' + r.phases.decap.median?.value.toFixed(4)}ms avg  (${r.phases.decap.throughput?.value.toFixed(0)} ops/s)`);
            if (r.phases.scalarMult) this.logCallback(`    scalarMult: ${r.phases.scalarMult.throughput  ? (1000/r.phases.scalarMult.throughput.value).toFixed(4) : r.phases.scalarMult.median?.value.toFixed(4)}ms avg  (${r.phases.scalarMult.throughput?.value.toFixed(0)} ops/s)`);
        }
        this.logCallback('');

        // ── SPACE COMPLEXITY ─────────────────────────────────────────────
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
        const smallestR = [ecdh, hybrid, twoKEM, hybrid2KEM].find(r => r.totalPayloadSize.value === smallest);
        this.logCallback(`  Most bandwidth-efficient: ${label(smallestR)} (${smallest.toFixed(0)} bytes)`);
        this.logCallback('');

        // ── SECURITY EFFICIENCY ──────────────────────────────────────────
        this.logCallback('SECURITY EFFICIENCY (security bits / payload byte)');
        this.logCallback('─────────────────────────────────────────────────────────────────');
        for (const r of [ecdh, hybrid, twoKEM, hybrid2KEM]) {
            this.logCallback(`  ${r.protocol.padEnd(42)} ${r.securityEfficiency.value.toFixed(4)} bits/byte`);
        }
        const bestSE = Math.max(...[ecdh, hybrid, twoKEM, hybrid2KEM].map(r => r.securityEfficiency.value));
        const bestSER = [ecdh, hybrid, twoKEM, hybrid2KEM].find(r => r.securityEfficiency.value === bestSE);
        this.logCallback(`  Best ratio: ${label(bestSER)} (${bestSE.toFixed(4)} bits/byte)`);
        this.logCallback('');

        // ── NETWORK IMPACT ───────────────────────────────────────────────
        if (this.networkProfile.latency > 0 || this.networkProfile.bandwidth < Infinity) {
            this.logCallback('NETWORK IMPACT');
            this.logCallback('─────────────────────────────────────────────────────────────────');
            this.logCallback(`  Profile: ${this.networkProfile.name}`);
            this.logCallback(`  ECDH avg network delay:      ${ecdh.avgNetworkDelay.value.toFixed(4)}ms`);
            this.logCallback(`  Hybrid avg network delay:    ${hybrid.avgNetworkDelay.value.toFixed(4)}ms`);
            this.logCallback(`  2-KEM avg network delay:     ${twoKEM.avgNetworkDelay.value.toFixed(4)}ms`);
            this.logCallback(`  Hybrid 2-KEM network delay:  ${hybrid2KEM.avgNetworkDelay.value.toFixed(4)}ms`);

            const lowestNetworkDelay = Math.min(ecdh.avgNetworkDelay.value, hybrid.avgNetworkDelay.value, twoKEM.avgNetworkDelay.value, hybrid2KEM.avgNetworkDelay.value);
            const lowestR = [ecdh, hybrid, twoKEM, hybrid2KEM].find(r => r.avgNetworkDelay.value === lowestNetworkDelay);
            this.logCallback(`  Lowest network delay: ${label(lowestR)}`);
            this.logCallback('');
        }

        // ── TOTAL TIME (compute + network) ───────────────────────────────
        const ecdhTotal     = ecdh.avgTimePerHandshake.value     + ecdh.avgNetworkDelay.value;
        const hybridTotal   = hybrid.avgTimePerHandshake.value   + hybrid.avgNetworkDelay.value;
        const twoKEMTotal   = twoKEM.avgTimePerHandshake.value   + twoKEM.avgNetworkDelay.value;
        const hybrid2KEMTotal = hybrid2KEM.avgTimePerHandshake.value + hybrid2KEM.avgNetworkDelay.value;

        this.logCallback('TOTAL TIME (Computation + Network)');
        this.logCallback('─────────────────────────────────────────────────────────────────');
        this.logCallback(`  ECDH:            ${ecdhTotal.toFixed(4)}ms`);
        this.logCallback(`  Hybrid:          ${hybridTotal.toFixed(4)}ms`);
        this.logCallback(`  2-KEM:           ${twoKEMTotal.toFixed(4)}ms`);
        this.logCallback(`  Hybrid 2-KEM:    ${hybrid2KEMTotal.toFixed(4)}ms`);

        const fastestTotal = Math.min(ecdhTotal, hybridTotal, twoKEMTotal, hybrid2KEMTotal);
        const fastestTotalR = [ecdh, hybrid, twoKEM, hybrid2KEM][[ecdhTotal, hybridTotal, twoKEMTotal, hybrid2KEMTotal].indexOf(fastestTotal)];
        this.logCallback(`  Winner: ${label(fastestTotalR)} (${fastestTotal.toFixed(4)}ms)`);
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
                timestamp: new Date().toISOString(),
                userAgent: typeof navigator !== 'undefined' ? navigator.userAgent : 'Node.js'
            },
            results: {
                ecdh:       this.results.ecdh,
                hybrid:     this.results.hybrid,
                twoKEM:     this.results.twoKEM,
                hybrid2KEM: this.results.hybrid2KEM
            },

            summary: ['ecdh', 'hybrid', 'twoKEM', 'hybrid2KEM'].map(key => {
                const r = this.results[key];
                if (!r) return null;
                return {
                    protocol:          r.protocol,
                    messageCount:      r.messageCount,
                    avgMs:             r.avgTimePerHandshake.value,
                    medianMs:          r.stats?.median?.value,
                    p95Ms:             r.stats?.p95?.value,
                    p99Ms:             r.stats?.p99?.value,
                    minMs:             r.stats?.min?.value,
                    maxMs:             r.stats?.max?.value,
                    stddevMs:          r.stats?.stddev?.value,
                    cvPct:             r.stats?.cv?.value,
                    throughput:        r.stats?.throughput?.value,
                    totalPayloadBytes: r.totalPayloadSize?.value,
                    avgNetworkDelayMs: r.avgNetworkDelay?.value,
                    securityEfficiency: r.securityEfficiency?.value,
                    phases: r.phases ? {
                        keygenAvgMs:     r.phases.keygen     ? (1000 / r.phases.keygen.throughput?.value)     : undefined,
                        encapAvgMs:      r.phases.encap      ? (1000 / r.phases.encap.throughput?.value)      : undefined,
                        decapAvgMs:      r.phases.decap      ? (1000 / r.phases.decap.throughput?.value)      : undefined,
                        scalarMultAvgMs: r.phases.scalarMult ? (1000 / r.phases.scalarMult.throughput?.value) : undefined
                    } : undefined
                };
            }).filter(Boolean)
        };
    }
}
