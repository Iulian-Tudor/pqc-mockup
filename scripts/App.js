// SPDX-FileCopyrightText: 2025 XWiki CryptPad Team <contact@cryptpad.org> and Iulian-Tudor Scutaru
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { runSimulation } from './simulation/Simulation.js';
import { ChartRenderer } from './visualization/ChartRenderer.js';
import { ENCRYPTOR_TYPES } from './utils/cryptoProvider.js';
import { HandshakeBenchmark } from './benchmark/HandshakeBenchmark.js';
import { NETWORK_PROFILES } from './benchmark/NetworkSimulator.js';
import { ModeSelector, MODES } from './ModeSelector.js';

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
        this.benchmarkSection = document.getElementById('benchmark-section');
        this.parametersSection = document.getElementById('parameters');
        this.outputSection = document.getElementById('output');

        this.isRunning = false;
        this.simulationCount = 0;
        this.currentMode = MODES.SIMULATION;

        this.modeSelector = new ModeSelector((mode) => this.switchMode(mode));
        this.setupEventListeners();
    }

    setupEventListeners() {
        this.form.addEventListener('submit', (e) => this.handleSubmit(e));
        this.resetButton.addEventListener('click', () => this.resetResults());
        this.cryptoSchemeSelect.addEventListener('change', () => this.togglePqcOptions());

        const inputs = this.form.querySelectorAll('input[type="number"]');
        inputs.forEach(input => {
            input.addEventListener('input', () => this.validateInput(input));
        });
    }

    switchMode(mode) {
        this.currentMode = mode;
        this.updateUIForMode(mode);
        this.resetResults();
    }

    updateUIForMode(mode) {
        if (mode === MODES.SIMULATION) {
            this.enableSimulationUI();
        } else if (mode === MODES.BENCHMARK) {
            this.enableBenchmarkUI();
        }
    }

    enableSimulationUI() {
        this.parametersSection.classList.remove('benchmark-mode');
        this.parametersSection.classList.add('simulation-mode');

        const paramGrid = this.parametersSection.querySelector('.parameter-grid');
        const distCheckbox = Array.from(this.parametersSection.querySelectorAll('.parameter-checkbox'))
            .find(el => el.querySelector('#useDistribution'));
        const encryptorItem = Array.from(this.parametersSection.querySelectorAll('.parameter-item'))
            .find(el => el.querySelector('#encryptorType'));
        const cryptoItem = Array.from(this.parametersSection.querySelectorAll('.parameter-item'))
            .find(el => el.querySelector('#cryptoScheme'));
        
        if (paramGrid) paramGrid.style.display = 'grid';
        if (distCheckbox) distCheckbox.style.display = 'flex';
        if (encryptorItem) encryptorItem.style.display = 'block';
        if (cryptoItem) cryptoItem.style.display = 'block';
        this.pqcOptionsContainer.style.display = this.cryptoSchemeSelect.value === 'pqc' ? 'block' : 'none';
        this.benchmarkSection.style.display = 'none';

        this.startButton.textContent = 'Start Simulation';
    }

    enableBenchmarkUI() {
        this.parametersSection.classList.remove('simulation-mode');
        this.parametersSection.classList.add('benchmark-mode');

        const paramGrid = this.parametersSection.querySelector('.parameter-grid');
        const distCheckbox = Array.from(this.parametersSection.querySelectorAll('.parameter-checkbox'))
            .find(el => el.querySelector('#useDistribution'));
        const encryptorItem = Array.from(this.parametersSection.querySelectorAll('.parameter-item'))
            .find(el => el.querySelector('#encryptorType'));
        const cryptoItem = Array.from(this.parametersSection.querySelectorAll('.parameter-item'))
            .find(el => el.querySelector('#cryptoScheme'));

        if (paramGrid) paramGrid.style.display = 'none';
        if (distCheckbox) distCheckbox.style.display = 'none';
        if (encryptorItem) encryptorItem.style.display = 'none';
        if (cryptoItem) cryptoItem.style.display = 'none';
        this.pqcOptionsContainer.style.display = 'none';
        this.benchmarkSection.style.display = 'block';

        this.startButton.textContent = 'Run Benchmark';
    }

    togglePqcOptions() {
        const showPqcOptions = this.cryptoSchemeSelect.value === 'pqc';
        this.pqcOptionsContainer.style.display = showPqcOptions ? 'block' : 'none';
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
        const vizContainer = document.createElement('div');
        vizContainer.className = 'visualization-container';

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

            if (this.currentMode === MODES.BENCHMARK) {
                await this.runBenchmark();
            } else {
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

        const iterations = parseInt(document.getElementById('benchmarkIterations').value) || 30000;
        const networkProfileValue = document.getElementById('networkProfile').value;
        
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
                this.startButton.textContent = this.currentMode === MODES.BENCHMARK ? 'Running Benchmark...' : 'Running...';
                break;
            case 'completed':
                this.startButton.textContent = this.currentMode === MODES.BENCHMARK ? 'Run Again' : 'Run Again';
                break;
            case 'error':
                this.startButton.textContent = 'Try Again';
                break;
            default:
                this.startButton.textContent = this.currentMode === MODES.BENCHMARK ? 'Run Benchmark' : 'Start Simulation';
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
        this.log('Results cleared. Ready for a new ' + (this.currentMode === MODES.BENCHMARK ? 'benchmark.' : 'simulation.'));
        this.updateUIState('ready');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.app = new SimulationApp();
});
