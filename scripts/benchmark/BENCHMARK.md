# PQC Handshake Benchmark Module

## Overview

This module implements a robust benchmarking system for comparing two Post-Quantum Key Exchange protocols:

1. **Protocol A: Hybrid Handshake (X25519 + Kyber-768)**
2. **Protocol B: Pure PQC "2-KEM" (Mutual Kyber-768)**

## Features

- 30,000 Iterations: High-volume testing for statistical significance
- JIT Warm-up: 1,000 warm-up iterations to ensure V8/SpiderMonkey optimization
- Network Simulation: Test under 4 different network profiles
- Accurate Timing: Uses `performance.now()` for microsecond precision
- Comprehensive Metrics: Time complexity, space complexity, and network impact

## Protocols Explained

### Protocol A: Hybrid Handshake (X25519 + Kyber-768)

**Advantages:**
- Smaller payloads (combines classical + PQC)
- Backward compatible with existing infrastructure
- Faster computation due to X25519 efficiency

**Steps:**
1. Alice generates ephemeral X25519 + Kyber-768 keypairs
2. Alice → Bob: X25519 PubKey (32B) + Kyber PubKey (1184B) = **1216 bytes**
3. Bob generates X25519 keypair, calculates shared secret, encapsulates Kyber secret
4. Bob → Alice: X25519 PubKey (32B) + Kyber Ciphertext (1088B) = **1120 bytes**
5. Alice calculates X25519 shared secret + decapsulates Kyber secret
6. Result: Concatenated shared secrets (64 bytes total)

**Total Payload: 2336 bytes**

### Protocol B: Pure PQC "2-KEM" (Mutual Kyber-768)

**Advantages:**
- No classical cryptography dependency
- Future-proof against quantum attacks on X25519
- Symmetric design (both parties use same algorithm)

**Setup:** Alice and Bob have static Kyber-768 public keys

**Steps:**
1. Alice encapsulates secret for Bob using his static public key
2. Alice → Bob: Kyber Ciphertext = **1088 bytes**
3. Bob encapsulates secret for Alice using her static public key
4. Bob → Alice: Kyber Ciphertext = **1088 bytes**
5. Both parties decapsulate received ciphertexts
6. Result: Combined shared secrets (64 bytes total)

**Total Payload: 2176 bytes**

## Network Profiles

### 1. High-Speed / Local
- **Latency:** 0ms
- **Bandwidth:** Unlimited
- **Use Case:** Measures pure CPU/computation efficiency

### 2. Mobile / 4G
- **Latency:** 50ms
- **Bandwidth:** 10 Mbps (1.25 MB/s)
- **Jitter:** ±10ms
- **Packet Loss:** 0.1%
- **Use Case:** Realistic mobile network conditions

### 3. Mobile / 3G
- **Latency:** 100ms
- **Bandwidth:** 3 Mbps (375 KB/s)
- **Jitter:** ±25ms
- **Packet Loss:** 1%
- **Use Case:** Lower-end mobile networks

### 4. Satellite
- **Latency:** 600ms
- **Bandwidth:** 1 Mbps (125 KB/s)
- **Jitter:** ±50ms
- **Packet Loss:** 2%
- **Use Case:** High-latency, constrained networks

## Usage

### In the UI

1. Check the **"Run PQC Handshake Benchmark"** checkbox
2. Configure parameters:
   - **Iterations:** 30,000 (default) - adjust for shorter/longer tests
   - **Network Profile:** Choose from High-Speed, Mobile 4G, 3G, or Satellite
3. Click **"Start Simulation"**
4. View results in the console output
5. Download results as JSON for further analysis

### Programmatic Usage

```javascript
import { HandshakeBenchmark } from './scripts/benchmark/HandshakeBenchmark.js';
import { NETWORK_PROFILES } from './scripts/benchmark/NetworkSimulator.js';

const benchmark = new HandshakeBenchmark({
    iterations: 30000,
    warmupIterations: 1000,
    networkProfile: NETWORK_PROFILES.MOBILE_4G,
    logCallback: (msg) => console.log(msg)
});

const results = await benchmark.runAll();
console.log(results);

// Export to JSON
const exportData = benchmark.exportResults();
```

## Output Metrics

### Time Complexity
- **Total Time:** Total execution time for all iterations
- **Average Time per Handshake:** Mean time in milliseconds
- **Performance Difference:** Percentage comparison between protocols

### Space Complexity
- **Payload 1 Size:** Alice → Bob message size
- **Payload 2 Size:** Bob → Alice message size
- **Total Payload:** Combined size for one handshake
- **Size Overhead:** Extra bytes required by 2-KEM vs Hybrid

### Network Impact
- **Average Network Delay:** Time spent in network transmission
- **Delay Impact:** How much extra payload affects latency on poor networks

## Expected Results

### High-Speed Networks
- **Hybrid** typically faster due to X25519 efficiency
- Payload size difference negligible (<5% impact)
- Computation dominates over network time

### Constrained Networks (4G, 3G, Satellite)
- **Hybrid** significantly faster due to smaller payload
- Extra 160 bytes in 2-KEM adds measurable latency
- Network delay dominates over computation time
- Demonstrates real-world advantage of hybrid approach

## Libraries Used

- @noble/post-quantum v0.4.0 - Kyber-768 (ML-KEM)
- tweetnacl v1.0.3 - X25519 key exchange
- tweetnacl-util v0.15.1 - Encoding utilities

## Performance Considerations

### JIT Warm-up
The benchmark runs 1,000 warm-up iterations before timing to ensure:
- V8 engine optimizes hot code paths
- Memory allocation patterns stabilize
- Cache effects normalize

### Timing Accuracy
Uses `performance.now()` which provides:
- Microsecond precision (1/1000 ms)
- Monotonic clock (unaffected by system time changes)
- Cross-browser compatibility

### Network Simulation
Accurately models:
- Base latency (propagation delay)
- Bandwidth constraints (transmission time)
- Jitter (latency variation)
- Packet loss (retransmission overhead)

## Dissertation Integration

This benchmark is designed for academic research comparing PQC protocols. Key features for dissertation use:

1. **Statistical Significance:** 30,000 iterations provide robust averages
2. **Real-World Scenarios:** Network profiles model actual deployment conditions
3. **Exportable Data:** JSON format for further statistical analysis
4. **Reproducible Results:** Fixed seeds and warm-up ensure consistency
5. **Comprehensive Metrics:** Time, space, and network impact all measured

## File Structure

```
scripts/benchmark/
├── HandshakeBenchmark.js    # Main benchmark implementation
├── NetworkSimulator.js      # Network condition simulation
└── BENCHMARK.md             # This documentation
```

## Future Enhancements

- Add support for other PQC schemes (Saber, FrodoKEM)
- Implement memory profiling (heap usage)
- Add CPU profiling (instruction counts)
- Support for different Kyber variants (512, 1024)
- WebWorker support for non-blocking execution
- Chart visualization of results

## License

SPDX-License-Identifier: AGPL-3.0-or-later

---

Author: Iulian-Tudor Scutaru  
Organization: XWiki CryptPad Team  
Year: 2025
