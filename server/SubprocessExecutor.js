// SPDX-FileCopyrightText: 2025 XWiki CryptPad Team <contact@cryptpad.org> and Iulian-Tudor Scutaru
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { spawn } from 'child_process';
import { resolve } from 'path';
import { fileURLToPath } from 'url';

const __dirname = resolve(fileURLToPath(import.meta.url), '..');

export class SubprocessExecutor {
    constructor(languageName, implementationDir) {
        this.languageName = languageName;
        this.implementationDir = resolve(__dirname, 'implementations', implementationDir);
        this.timeout = 60000;
    }

    async execute(benchmarkConfig) {
        return new Promise((resolve, reject) => {
            const process = spawn(this.getCommand(), this.getArgs(benchmarkConfig), {
                cwd: this.implementationDir,
                timeout: this.timeout,
                stdio: ['pipe', 'pipe', 'pipe']
            });

            let stdout = '';
            let stderr = '';

            process.stdout.on('data', (data) => {
                stdout += data.toString();
            });

            process.stderr.on('data', (data) => {
                stderr += data.toString();
            });

            process.on('close', (code) => {
                if (code !== 0) {
                    reject(new Error(`${this.languageName} process failed: ${stderr}`));
                } else {
                    try {
                        const result = JSON.parse(stdout);
                        resolve(result);
                    } catch (e) {
                        reject(new Error(`Failed to parse ${this.languageName} output: ${e.message}`));
                    }
                }
            });

            process.on('error', (error) => {
                reject(new Error(`Failed to spawn ${this.languageName} process: ${error.message}`));
            });
        });
    }

    getCommand() {
        const commands = {
            'rust': 'cargo',
            'python': 'python3',
            'go': 'go',
            'java': 'java',
            'javascript': 'node',
            'cpp': './benchmark',
            'csharp': 'dotnet'
        };
        return commands[this.languageName] || 'node';
    }

    getArgs(benchmarkConfig) {
        const baseArgs = [
            `--iterations=${benchmarkConfig.benchmarkRuns}`,
            `--warmup=${benchmarkConfig.warmupRuns}`,
            `--output=json`
        ];

        switch (this.languageName) {
            case 'rust':
                return ['run', '--release', '--', ...baseArgs];
            case 'python':
                return ['benchmark.py', ...baseArgs];
            case 'go':
                return ['run', 'benchmark.go', ...baseArgs];
            case 'java':
                return ['-jar', 'benchmark.jar', ...baseArgs];
            case 'javascript':
                return ['benchmark.js', ...baseArgs];
            case 'cpp':
                return baseArgs;
            case 'csharp':
                return ['run', ...baseArgs];
            default:
                return baseArgs;
        }
    }

    validateSetup() {
        try {
            const fs = require('fs');
            const stats = fs.statSync(this.implementationDir);
            return stats.isDirectory();
        } catch (error) {
            throw new Error(`Implementation directory not found for ${this.languageName}: ${this.implementationDir}`);
        }
    }
}
