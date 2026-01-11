# PQC Handshake Benchmark

## Overview

Benchmarks four key exchange protocols with 30,000 iterations and network simulation:

1. **Pure ECDH (X25519)** - Classic Diffie-Hellman baseline
2. **Hybrid (X25519 + Kyber-768)** - Single-sided PQC + backwards compatible
3. **Pure 2-KEM (Mutual Kyber-768)** - Bilateral PQC, no classical fallback
4. **Hybrid 2-KEM (X25519 + 2×Kyber)** - Bilateral PQC + backwards compatible

## Key Features

- **30,000 iterations** with 1,000 JIT warm-up for statistical significance
- **4 network profiles**: High-Speed, Mobile 4G/3G, Satellite
- **Accurate timing** via `performance.now()` (microsecond precision)
- **Metrics**: Time complexity, space complexity, network impact

## Protocol Comparison

| Protocol | Payload Size | Messages | PQC Security | Classical Security |
|----------|--------------|----------|--------------|-------------------|
| Pure ECDH | 64 bytes | 2 | No | Yes |
| Hybrid | ~2.3 KB | 2 | Yes (single) | Yes |
| Pure 2-KEM | ~2.2 KB | 2 | Yes (bilateral) | No |
| Hybrid 2-KEM | ~3.4 KB | 3 | Yes (bilateral) | Yes |

## Network Profiles

- **High-Speed**: 0ms latency, unlimited bandwidth (pure computation test)
- **Mobile 4G**: 50ms latency, 10 Mbps, ±10ms jitter
- **Mobile 3G**: 100ms latency, 3 Mbps, ±25ms jitter
- **Satellite**: 600ms latency, 1 Mbps, ±50ms jitter

## Usage

### UI
1. Check "Run PQC Handshake Benchmark"
2. Set iterations (default: 30,000) and network profile
3. Click "Start Simulation"

### Programmatic

```javascript
import { HandshakeBenchmark } from './scripts/benchmark/HandshakeBenchmark.js';
import { NETWORK_PROFILES } from './scripts/benchmark/NetworkSimulator.js';

const benchmark = new HandshakeBenchmark({
    iterations: 30000,
    networkProfile: NETWORK_PROFILES.MOBILE_4G
});

const results = await benchmark.runAll();
const exportData = benchmark.exportResults();
```

## Output Metrics

- **Time**: Total time, average per handshake, fastest protocol
- **Space**: Payload sizes, total bandwidth, most efficient
- **Network**: Transmission delays, impact of payload size
- **Total**: Computation + network, overall winner

## Expected Results

**High-Speed Networks**: Pure ECDH fastest, Hybrid close second, payload overhead minimal

**Constrained Networks**: Hybrid 2-KEM trades ~1KB extra payload for bilateral PQC entropy; acceptable on 4G+

## Libraries

- `@noble/post-quantum` v0.4.0 - Kyber-768 (ML-KEM)
- `tweetnacl` v1.0.3 - X25519 and random number generation

## License

SPDX-License-Identifier: AGPL-3.0-or-later

---

Author: Iulian-Tudor Scutaru  
Organization: XWiki CryptPad Team  
Year: 2025
