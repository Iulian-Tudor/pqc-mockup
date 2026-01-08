// SPDX-FileCopyrightText: 2025 XWiki CryptPad Team <contact@cryptpad.org> and Iulian-Tudor Scutaru
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { runSimulation } from './simulation/Simulation.js';
import { ChartRenderer } from './visualization/ChartRenderer.js';
import { ENCRYPTOR_TYPES } from './utils/cryptoProvider.js';
import { HandshakeBenchmark } from './benchmark/HandshakeBenchmark.js';
import { NETWORK_PROFILES } from './benchmark/NetworkSimulator.js';

class SimulationApp {
    constructor() {
        this.form = document.getElementById('simulation-form');
        this.startButton = document.getElementById('startButton');
        this.resetButton = document.getElementById('resetButton');
        this.logElement = document.getElementById('simulation-log');
        this.resultsElement = document.getElementById('results');
        this.statusIndicator = document.getElementById('status-indicator');
        this.cryptoSchemeSelect = document.getElementById('cryptoScheme');
        this.pqcOptionsContainer = document.getElementById('pqc-options');
        this.enableBenchmarkCheckbox = document.getElementById('enableBenchmark');
        this.benchmarkOptionsContainer = document.getElementById('benchmark-options');

        this.isRunning = false;
        this.simulationCount = 0;

        this.setupEventListeners();

        this.togglePqcOptions();
        this.toggleBenchmarkOptions();
    }

    setupEventListeners() {
        this.form.addEventListener('submit', (e) => this.handleSubmit(e));
        this.resetButton.addEventListener('click', () => this.resetResults());
        this.cryptoSchemeSelect.addEventListener('change', () => this.togglePqcOptions());
        this.enableBenchmarkCheckbox.addEventListener('change', () => this.toggleBenchmarkOptions());

        const inputs = this.form.querySelectorAll('input[type="number"]');
        inputs.forEach(input => {
            input.addEventListener('input', () => this.validateInput(input));
        });
    }
    
    togglePqcOptions() {
        const showPqcOptions = this.cryptoSchemeSelect.value === 'pqc';
        this.pqcOptionsContainer.style.display = showPqcOptions ? 'block' : 'none';
    }

    toggleBenchmarkOptions() {
        const showBenchmarkOptions = this.enableBenchmarkCheckbox.checked;
        this.benchmarkOptionsContainer.style.display = showBenchmarkOptions ? 'block' : 'none';
    }

    validateInput(input) {
        const value = parseInt(input.value);
        const min = parseInt(input.min);
        const max = parseInt(input.max);

        if (isNaN(value) || value < min || value > max) {
            input.setCustomValidity(`Value must be between ${min} and ${max}`);
        } else {
            input.setCustomValidity('');
        }
    }

    renderVisualizations(analysisData) {
        // Create container for visualizations
        const vizContainer = document.createElement('div');
        vizContainer.className = 'visualization-container';

        // Create section for JSON download
        const downloadSection = document.createElement('div');
        downloadSection.className = 'download-section';

        const downloadButton = document.createElement('button');
        downloadButton.textContent = 'Download Complete Data (JSON)';
        downloadButton.className = 'primary-button download-json';
        downloadButton.addEventListener('click', () => {
            const jsonString = JSON.stringify(analysisData, null, 2);
            const blob = new Blob([jsonString], { type: 'application/json' });
            const url = URL.createObjectURL(blob);

            const a = document.createElement('a');
            a.href = url;
            a.download = 'simulation-analysis.json';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        });

        downloadSection.appendChild(downloadButton);
        vizContainer.appendChild(downloadSection);

        // Create sections for each chart
        const charts = [
            { id: 'edit-distribution', title: 'Edit Distribution Curve', renderer: 'renderEditDistribution' },
            { id: 'user-document-network', title: 'User-Document Network Graph', renderer: 'renderUserDocumentNetwork' },
            { id: 'performance-over-time', title: 'Performance Over Simulation Time', renderer: 'renderPerformanceOverTime' },
            { id: 'crypto-size-comparison', title: 'Cryptographic Size Comparison', renderer: 'renderSizeComparison' }
        ];

        charts.forEach(chart => {
            const section = document.createElement('section');
            section.className = 'chart-section';

            const heading = document.createElement('h3');
            heading.textContent = chart.title;

            const chartContainer = document.createElement('div');
            chartContainer.id = chart.id;
            chartContainer.className = 'chart-container';

            section.appendChild(heading);
            section.appendChild(chartContainer);
            vizContainer.appendChild(section);
        });

        this.resultsElement.appendChild(vizContainer);

        // Initialize the chart renderer and render all charts
        const chartRenderer = new ChartRenderer(analysisData);
        charts.forEach(chart => {
            chartRenderer[chart.renderer](chart.id);
        });
    }

    async handleSubmit(event) {
        event.preventDefault();

        if (this.isRunning) return;

        try {
            this.isRunning = true;
            this.simulationCount++;
            this.updateUIState('running');

            // Check if benchmark mode is enabled
            const enableBenchmark = document.getElementById('enableBenchmark').checked;

            if (enableBenchmark) {
                // Run PQC Handshake Benchmark
                await this.runBenchmark();
            } else {
                // Run normal simulation
                const params = this.getSimulationParameters();
                this.log(`Using crypto scheme: ${params.cryptoScheme}`, 'info');

                if (params.cryptoScheme === 'pqc' && params.kem && params.signature) {
                    this.log(`Using ${params.kem} + ${params.signature}`, 'info');
                }

                const startTime = performance.now();

                if (this.resultsElement.children.length === 0) {
                    this.resetLog();
                }

                const result = await runSimulation(params);

                const executionTime = performance.now() - startTime;

                if (result && result.analytics) {
                    result.analytics.setExecutionTime(executionTime);
                    this.renderVisualizations(result.analytics);
                    this.log(`Simulation completed in ${(executionTime / 1000).toFixed(2)} seconds`);
                }
            }
        } catch (error) {
            this.log(`Simulation error: ${error.message}`, 'error');
            console.error('Simulation error:', error);
        } finally {
            this.isRunning = false;
            this.updateUIState('complete');
        }
    }

    async runBenchmark() {
        this.log('=== Starting PQC Handshake Benchmark ===', 'info');
        this.log('This will compare Hybrid (X25519+Kyber-768) vs Pure PQC 2-KEM protocols', 'info');
        this.log('', 'info');

        // Get benchmark parameters
        const iterations = parseInt(document.getElementById('benchmarkIterations').value) || 30000;
        const networkProfileValue = document.getElementById('networkProfile').value;
        
        // Map network profile selection to NETWORK_PROFILES
        let networkProfile;
        switch (networkProfileValue) {
            case 'high-speed':
                networkProfile = NETWORK_PROFILES.HIGH_SPEED;
                break;
            case 'mobile-4g':
                networkProfile = NETWORK_PROFILES.MOBILE_4G;
                break;
            case 'mobile-3g':
                networkProfile = NETWORK_PROFILES.MOBILE_3G;
                break;
            case 'satellite':
                networkProfile = NETWORK_PROFILES.SATELLITE;
                break;
            default:
                networkProfile = NETWORK_PROFILES.HIGH_SPEED;
        }

        try {
            const benchmark = new HandshakeBenchmark({
                iterations: iterations,
                warmupIterations: 1000,
                networkProfile: networkProfile,
                logCallback: (msg) => this.log(msg, 'info')
            });

            const results = await benchmark.runAll();

            // Display results and download option
            this.renderBenchmarkResults(results, benchmark);

        } catch (error) {
            this.log(`Benchmark error: ${error.message}`, 'error');
            console.error('Benchmark error:', error);
        }
    }

    renderBenchmarkResults(results, benchmark) {
        const resultsContainer = document.createElement('div');
        resultsContainer.className = 'benchmark-results-container';
        resultsContainer.style.marginTop = '20px';
        resultsContainer.style.padding = '20px';
        resultsContainer.style.backgroundColor = '#f8f9fa';
        resultsContainer.style.borderRadius = '8px';

        const title = document.createElement('h3');
        title.textContent = 'Benchmark Results Summary';
        title.style.color = '#2ecc71';
        title.style.marginBottom = '15px';
        resultsContainer.appendChild(title);

        const downloadButton = document.createElement('button');
        downloadButton.textContent = 'Download Benchmark Results (JSON)';
        downloadButton.className = 'primary-button';
        downloadButton.style.marginTop = '10px';
        downloadButton.addEventListener('click', () => {
            const data = benchmark.exportResults();
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `pqc-benchmark-${new Date().toISOString().split('T')[0]}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        });
        resultsContainer.appendChild(downloadButton);

        this.resultsElement.appendChild(resultsContainer);
    }

    getSimulationParameters() {
        const encryptorType = document.getElementById('encryptorType').value;
        console.log(`Using encryptor type: ${encryptorType}`);
        
        const params = {
            numUsers: parseInt(document.getElementById('numUsers').value, 10),
            numDocuments: parseInt(document.getElementById('numDocuments').value, 10),
            maxEditsPerUser: parseInt(document.getElementById('maxEditsPerUser').value, 10),
            logFrequency: parseInt(document.getElementById('logFrequency').value, 10),
            useDistribution: document.getElementById('useDistribution').checked,
            cryptoScheme: document.getElementById('cryptoScheme').value,
            encryptorType: encryptorType
        };

        if (params.cryptoScheme === 'pqc') {
            params.kem = document.getElementById('kemScheme').value;
            params.signature = document.getElementById('signatureScheme').value;
        }
        
        return params;
    }

    updateUIState(state) {
        this.startButton.disabled = (state === 'running');
        this.resetButton.disabled = (state === 'running');

        switch (state) {
            case 'running':
                this.startButton.textContent = 'Running...';
                break;
            case 'completed':
                this.startButton.textContent = 'Run Again';
                break;
            case 'error':
                this.startButton.textContent = 'Try Again';
                break;
            default:
                this.startButton.textContent = 'Start Simulation';
        }

        this.statusIndicator.textContent = state.charAt(0).toUpperCase() + state.slice(1);
        this.statusIndicator.className = 'status-indicator ' + state;

        if (state === 'running') {
            this.logElement.classList.add('running-animation');
        } else {
            this.logElement.classList.remove('running-animation');
        }
    }

    log(message, type = 'info') {
        if (!this.logElement) return;

        const timestamp = new Date().toLocaleTimeString();
        const formattedMessage = `[${timestamp}] ${message}`;

        const messageEl = document.createElement('div');
        messageEl.innerHTML = formattedMessage;

        if (type === 'error') {
            messageEl.style.color = 'var(--danger)';
        } else if (type === 'success') {
            messageEl.style.color = 'var(--success)';
        }

        this.logElement.appendChild(messageEl);
        this.logElement.scrollTop = this.logElement.scrollHeight;
    }

    resetLog() {
        if (this.logElement) {
            this.logElement.innerHTML = '';
        }
    }

    resetResults() {
        if (this.resultsElement) {
            this.resultsElement.innerHTML = '';
        }

        this.resetLog();
        this.log('Results cleared. Ready for a new simulation.');
        this.updateUIState('ready');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.app = new SimulationApp();
});

