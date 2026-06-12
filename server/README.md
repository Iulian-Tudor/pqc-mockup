# Multi-Language PQC Benchmark Server

Server-side module for benchmarking PQC handshake implementations across different programming languages.

## Architecture

```
server/
├── constants.js                    - Language definitions and metadata
├── LanguageBenchmarkRunner.js      - Orchestrates benchmark execution
├── SubprocessExecutor.js           - Spawns language-specific subprocesses
├── LanguageBenchmarkAnalyzer.js    - Analyzes and compares results
├── api.js                          - Express API endpoints (future)
├── implementations/                - Language implementations
│   ├── rust/
│   ├── python/
│   ├── go/
│   ├── java/
│   ├── javascript/
│   ├── cpp/
│   └── csharp/
└── README.md                       - This file
```

## Core Components

### LanguageBenchmarkRunner
Orchestrates benchmark execution across multiple languages:
- Accepts configuration (languages, iterations, protocols)
- Executes benchmarks sequentially or in parallel
- Collects and aggregates results
- Handles errors gracefully

```javascript
import { LanguageBenchmarkRunner } from './LanguageBenchmarkRunner.js';

const runner = new LanguageBenchmarkRunner({
    languages: ['rust', 'python', 'go', 'javascript'],
    benchmarkRuns: 1000,
    warmupRuns: 100,
    protocols: ['hybrid', 'pure2kem']
});

const results = await runner.runAllLanguages();
```

### SubprocessExecutor
Spawns and manages language-specific benchmark processes:
- Handles process spawning with proper error handling
- Manages timeouts and resource cleanup
- Parses JSON output from subprocesses
- Language-agnostic argument passing

```javascript
import { SubprocessExecutor } from './SubprocessExecutor.js';

const executor = new SubprocessExecutor('rust', 'rust');
const result = await executor.execute({
    benchmarkRuns: 1000,
    warmupRuns: 100
});
```

### LanguageBenchmarkAnalyzer
Analyzes and compares benchmark results:
- Compares languages across protocols
- Calculates statistics (fastest, slowest, consistency)
- Generates reports with recommendations
- Exports results in multiple formats (JSON, CSV)

```javascript
import { LanguageBenchmarkAnalyzer } from './LanguageBenchmarkAnalyzer.js';

const analyzer = new LanguageBenchmarkAnalyzer(results);
const report = analyzer.generateReport();
const csv = analyzer.exportCSV();
```

## Usage

### Run Single Language Benchmark

```bash
cd server/implementations/rust
cargo run --release -- --iterations=1000 --warmup=100 --output=json
```

### Run All Languages (Future API)

```bash
# Via API endpoint (when implemented)
curl -X POST http://localhost:3000/api/benchmark/languages \
  -H "Content-Type: application/json" \
  -d '{
    "languages": ["rust", "python", "go"],
    "benchmarkRuns": 1000,
    "warmupRuns": 100
  }'
```

## Implementation Status

- [x] Core framework and interfaces
- [x] LanguageBenchmarkRunner scaffold
- [x] SubprocessExecutor with language command mapping
- [x] LanguageBenchmarkAnalyzer with comparison logic
- [ ] Rust implementation
- [ ] Python implementation
- [ ] Go implementation
- [ ] Java implementation
- [ ] C++ implementation
- [ ] C# implementation
- [ ] Express API endpoints
- [ ] UI integration with frontend mode selector

## Next Steps

1. **Implement individual language benchmarks** - Start with Rust and Python
2. **Create Express API** - `api.js` with `/benchmark/languages` endpoint
3. **Add UI integration** - New "Polyglot Benchmark" mode in frontend
4. **Implement caching** - Store results to avoid repeated slow benchmarks
5. **Add parallel execution** - Run multiple languages concurrently

## Environment Requirements

Each language implementation requires:
- **Rust**: `rustc` >= 1.60, `cargo`
- **Python**: `python3` >= 3.8, `pip`
- **Go**: `go` >= 1.16
- **Java**: `openjdk` >= 11
- **JavaScript**: `node` >= 14
- **C++**: `g++` >= 9 or `clang` >= 10
- **C#**: `.NET SDK` >= 6.0

PQC libraries will be installed via language-specific package managers.

## Output Format

Each implementation outputs standardized JSON:

```json
{
  "language": "rust",
  "version": "1.70.0",
  "timestamp": "2025-06-12T10:30:00Z",
  "config": {
    "iterations": 1000,
    "warmupRuns": 100
  },
  "benchmarks": {
    "hybrid": {
      "mean": 0.456,
      "median": 0.450,
      "stddev": 0.025,
      "min": 0.400,
      "max": 0.550,
      "runs": 1000
    },
    "pure2kem": {
      "mean": 0.583,
      "median": 0.580,
      "stddev": 0.030,
      "min": 0.500,
      "max": 0.700,
      "runs": 1000
    }
  },
  "metadata": {
    "duration_seconds": 45.2,
    "environment": "Linux x86_64",
    "processor": "Intel(R) Core(TM) i9-12900K"
  }
}
```

## Notes

- All benchmarks measure the same operations (keygen, encap, decap)
- Results are normalized to milliseconds for comparison
- Implementations should use native PQC libraries, not JavaScript bindings
- Statistical outliers should be handled consistently across languages
