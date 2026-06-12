// SPDX-FileCopyrightText: 2025 XWiki CryptPad Team <contact@cryptpad.org> and Iulian-Tudor Scutaru
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import express from 'express';
import { LanguageBenchmarkRunner } from './LanguageBenchmarkRunner.js';
import { LanguageBenchmarkAnalyzer } from './LanguageBenchmarkAnalyzer.js';
import { SUPPORTED_LANGUAGES, LANGUAGE_INFO } from './constants.js';

const router = express.Router();

router.get('/languages', (req, res) => {
    res.json({
        supported: Object.values(SUPPORTED_LANGUAGES),
        info: LANGUAGE_INFO
    });
});

router.post('/benchmark/languages', async (req, res) => {
    try {
        const { languages, benchmarkRuns, warmupRuns, protocols } = req.body;

        if (!languages || languages.length === 0) {
            return res.status(400).json({
                error: 'At least one language must be specified'
            });
        }

        const runner = new LanguageBenchmarkRunner({
            languages,
            benchmarkRuns: benchmarkRuns || 1000,
            warmupRuns: warmupRuns || 100,
            protocols: protocols || ['hybrid', 'pure2kem']
        });

        runner.validateConfig();

        res.json({
            status: 'running',
            message: 'Multi-language benchmark started',
            config: {
                languages,
                benchmarkRuns,
                warmupRuns,
                protocols
            }
        });

        const results = await runner.runAllLanguages();

        res.json({
            status: 'completed',
            results
        });

    } catch (error) {
        res.status(500).json({
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

router.post('/benchmark/languages/async', async (req, res) => {
    try {
        const { languages, benchmarkRuns, warmupRuns, protocols } = req.body;

        const jobId = `job_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

        res.json({
            status: 'queued',
            jobId,
            message: 'Benchmark job queued for asynchronous execution'
        });

        const runner = new LanguageBenchmarkRunner({
            languages,
            benchmarkRuns: benchmarkRuns || 1000,
            warmupRuns: warmupRuns || 100,
            protocols: protocols || ['hybrid', 'pure2kem']
        });

        runner.runAllLanguages()
            .then(results => {
                console.log(`Benchmark ${jobId} completed`);
            })
            .catch(error => {
                console.error(`Benchmark ${jobId} failed:`, error);
            });

    } catch (error) {
        res.status(500).json({
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

router.post('/analyze', (req, res) => {
    try {
        const { results } = req.body;

        if (!results) {
            return res.status(400).json({
                error: 'Results object is required'
            });
        }

        const analyzer = new LanguageBenchmarkAnalyzer(results);
        const report = analyzer.generateReport();

        res.json(report);

    } catch (error) {
        res.status(500).json({
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

router.post('/export/csv', (req, res) => {
    try {
        const { results } = req.body;

        if (!results) {
            return res.status(400).json({
                error: 'Results object is required'
            });
        }

        const analyzer = new LanguageBenchmarkAnalyzer(results);
        const csv = analyzer.exportCSV();

        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename=pqc-benchmark-comparison.csv');
        res.send(csv);

    } catch (error) {
        res.status(500).json({
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

export default router;
