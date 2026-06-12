// SPDX-FileCopyrightText: 2025 XWiki CryptPad Team <contact@cryptpad.org> and Iulian-Tudor Scutaru
//
// SPDX-License-Identifier: AGPL-3.0-or-later

export const SUPPORTED_LANGUAGES = {
    RUST: 'rust',
    PYTHON: 'python',
    GOLANG: 'go',
    JAVA: 'java',
    JAVASCRIPT: 'javascript',
    CPP: 'cpp',
    CSHARP: 'csharp'
};

export const LANGUAGE_INFO = {
    [SUPPORTED_LANGUAGES.RUST]: {
        name: 'Rust',
        description: 'Systems programming with memory safety',
        ecosystem: 'liboqs-rust, pqcrypto',
        performanceNote: 'Very fast, zero-cost abstractions'
    },
    [SUPPORTED_LANGUAGES.PYTHON]: {
        name: 'Python',
        description: 'Easy scripting with bindings',
        ecosystem: 'liboqs-python, OQS provider',
        performanceNote: 'Slower, but great for prototyping'
    },
    [SUPPORTED_LANGUAGES.GOLANG]: {
        name: 'Go',
        description: 'Concurrent and efficient',
        ecosystem: 'liboqs-go, Open Quantum Safe',
        performanceNote: 'Fast goroutines, excellent for concurrent benchmarks'
    },
    [SUPPORTED_LANGUAGES.JAVA]: {
        name: 'Java',
        description: 'JVM-based with strong ecosystem',
        ecosystem: 'liboqs-java, Bouncy Castle',
        performanceNote: 'JIT compilation, good for long-running benchmarks'
    },
    [SUPPORTED_LANGUAGES.JAVASCRIPT]: {
        name: 'JavaScript (Node.js)',
        description: 'Current implementation',
        ecosystem: '@noble/post-quantum',
        performanceNote: 'V8 optimized, matches web implementation'
    },
    [SUPPORTED_LANGUAGES.CPP]: {
        name: 'C++',
        description: 'Raw performance and control',
        ecosystem: 'liboqs-cpp, modern C++17+',
        performanceNote: 'Baseline performance reference'
    },
    [SUPPORTED_LANGUAGES.CSHARP]: {
        name: 'C# / .NET',
        description: '.NET ecosystem integration',
        ecosystem: 'liboqs-dotnet, .NET 6+',
        performanceNote: 'JIT compiled, good for Windows environments'
    }
};
