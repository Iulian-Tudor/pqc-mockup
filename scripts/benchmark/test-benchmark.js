// SPDX-FileCopyrightText: 2025 XWiki CryptPad Team <contact@cryptpad.org> and Iulian-Tudor Scutaru
//
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Test script for PQC Handshake Benchmark
 * Run this in Node.js to verify the benchmark works correctly
 * 
 * Usage: node test-benchmark.js
 */

import { HandshakeBenchmark } from './HandshakeBenchmark.js';
import { NETWORK_PROFILES } from './NetworkSimulator.js';

async function runTest() {
    console.log('Testing PQC Handshake Benchmark\n');

    const benchmark = new HandshakeBenchmark({
        iterations: 100,          
        warmupIterations: 10,    
        networkProfile: NETWORK_PROFILES.HIGH_SPEED,
        logCallback: (msg) => console.log(msg)
    });

    try {
        console.log('Starting benchmark test...\n');
        const results = await benchmark.runAll();

        console.log('\nBenchmark test completed successfully!');
        console.log('\nResults object:', JSON.stringify(results, null, 2));

        const exportData = benchmark.exportResults();
        console.log('\nExport functionality works!');
        console.log('Export metadata:', exportData.metadata);

    } catch (error) {
        console.error('\nBenchmark test failed:', error);
        console.error('Stack trace:', error.stack);
        process.exit(1);
    }
}

runTest().then(() => {
    console.log('\nAll tests passed!');
    process.exit(0);
}).catch(error => {
    console.error('\nTest execution failed:', error);
    process.exit(1);
});
