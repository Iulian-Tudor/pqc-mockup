# PQC Multi-Language Benchmark Implementations

Directory structure for language-specific PQC handshake benchmark implementations.

Each language directory should contain:

## Directory Structure

```
implementations/
├── rust/
│   ├── Cargo.toml
│   ├── src/
│   │   └── main.rs
│   └── README.md
├── python/
│   ├── requirements.txt
│   ├── benchmark.py
│   └── README.md
├── go/
│   ├── go.mod
│   ├── benchmark.go
│   └── README.md
├── java/
│   ├── pom.xml
│   ├── src/
│   │   └── main/java/
│   │       └── PQCBenchmark.java
│   └── README.md
├── javascript/
│   ├── package.json
│   ├── benchmark.js
│   └── README.md
├── cpp/
│   ├── CMakeLists.txt
│   ├── benchmark.cpp
│   └── README.md
└── csharp/
    ├── csproj file
    ├── Program.cs
    └── README.md
```

## Implementation Requirements

Each implementation should:

1. **Accept CLI arguments:**
   - `--iterations=N` - Number of benchmark runs
   - `--warmup=N` - Number of warmup runs
   - `--output=json` - Output format (always JSON)

2. **Output JSON with structure:**
```json
{
  "language": "rust",
  "version": "1.x.x",
  "timestamp": "2025-06-12T00:00:00Z",
  "config": {
    "iterations": 1000,
    "warmupRuns": 100
  },
  "benchmarks": {
    "hybrid": {
      "keygen_time_ms": 0.123,
      "encap_time_ms": 0.456,
      "decap_time_ms": 0.789,
      "runs": 1000,
      "mean": 0.456,
      "median": 0.450,
      "stddev": 0.025,
      "min": 0.400,
      "max": 0.550
    },
    "pure2kem": {
      "keygen_time_ms": 0.200,
      "encap_time_ms": 0.600,
      "decap_time_ms": 0.950,
      "runs": 1000,
      "mean": 0.583,
      "median": 0.580,
      "stddev": 0.030,
      "min": 0.500,
      "max": 0.700
    }
  },
  "metadata": {
    "duration_seconds": 45.2,
    "environment": "Linux x86_64",
    "processor": "Intel(R) Core(TM) i9-12900K"
  }
}
```

3. **Error handling:**
   - Exit with code 1 on error
   - Output error details to stderr
   - Catch and report missing dependencies

## Libraries to Use

- **Rust**: `liboqs-rust` or `pqcrypto`
- **Python**: `liboqs` (python bindings)
- **Go**: `liboqs-go` from Open Quantum Safe
- **Java**: `liboqs-java` or `org.bouncycastle.pqc`
- **JavaScript**: `@noble/post-quantum` (existing)
- **C++**: `liboqs-cpp` or direct `liboqs` bindings
- **C#**: `liboqs-dotnet` or `Org.BouncyCastle.Pqc`

## Testing

Each implementation can be tested independently:

```bash
cd implementations/rust
cargo run --release -- --iterations=100 --warmup=10 --output=json
```

## Notes

- All implementations should test the same algorithms (ML-KEM-768, ML-DSA-65)
- Timing should be as precise as possible (nanoseconds when available)
- Implementations should handle network profiles simulators (latency injection)
- Results must be JSON-serializable for aggregation by LanguageBenchmarkRunner
