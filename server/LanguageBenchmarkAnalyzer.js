// SPDX-FileCopyrightText: 2025 XWiki CryptPad Team <contact@cryptpad.org> and Iulian-Tudor Scutaru
//
// SPDX-License-Identifier: AGPL-3.0-or-later

export class LanguageBenchmarkAnalyzer {
    constructor(results) {
        this.results = results;
    }

    compareLanguages() {
        const comparison = {
            by_protocol: {},
            by_language: {},
            statistics: this.calculateStatistics()
        };

        for (const lang of Object.keys(this.results)) {
            const langData = this.results[lang];
            if (langData.benchmarks) {
                for (const protocol of Object.keys(langData.benchmarks)) {
                    if (!comparison.by_protocol[protocol]) {
                        comparison.by_protocol[protocol] = {};
                    }
                    comparison.by_protocol[protocol][lang] = langData.benchmarks[protocol];
                }
            }
            comparison.by_language[lang] = langData;
        }

        return comparison;
    }

    calculateStatistics() {
        const stats = {
            fastest_languages: [],
            slowest_languages: [],
            average_overhead: {},
            consistency: {}
        };

        const languages = Object.keys(this.results);
        if (languages.length === 0) return stats;

        const avgTimes = {};
        for (const lang of languages) {
            const langData = this.results[lang];
            if (langData.benchmarks && langData.benchmarks.hybrid) {
                avgTimes[lang] = langData.benchmarks.hybrid.mean || 0;
            }
        }

        const sorted = Object.entries(avgTimes).sort((a, b) => a[1] - b[1]);
        stats.fastest_languages = sorted.slice(0, 3).map(([lang]) => lang);
        stats.slowest_languages = sorted.slice(-3).reverse().map(([lang]) => lang);

        return stats;
    }

    generateReport() {
        const comparison = this.compareLanguages();
        
        return {
            timestamp: new Date().toISOString(),
            summary: {
                total_languages: Object.keys(this.results).length,
                protocols_tested: Object.keys(comparison.by_protocol),
                fastest: comparison.statistics.fastest_languages,
                slowest: comparison.statistics.slowest_languages
            },
            details: comparison,
            recommendations: this.generateRecommendations()
        };
    }

    generateRecommendations() {
        return {
            production: 'C++ or Rust for maximum performance',
            prototyping: 'Python for ease of development',
            embedded: 'Rust for memory safety without overhead',
            concurrent_workloads: 'Go for excellent goroutine scaling',
            dotnet_environments: 'C# for .NET ecosystem integration'
        };
    }

    exportCSV() {
        const headers = ['Language', 'Protocol', 'Mean (ms)', 'Median (ms)', 'StdDev', 'Min', 'Max'];
        const rows = [];

        for (const [lang, data] of Object.entries(this.results)) {
            if (data.benchmarks) {
                for (const [protocol, metrics] of Object.entries(data.benchmarks)) {
                    rows.push([
                        lang,
                        protocol,
                        metrics.mean?.toFixed(4) || 'N/A',
                        metrics.median?.toFixed(4) || 'N/A',
                        metrics.stddev?.toFixed(4) || 'N/A',
                        metrics.min?.toFixed(4) || 'N/A',
                        metrics.max?.toFixed(4) || 'N/A'
                    ]);
                }
            }
        }

        return [headers, ...rows].map(row => row.join(',')).join('\n');
    }
}
