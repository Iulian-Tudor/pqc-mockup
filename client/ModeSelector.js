// SPDX-FileCopyrightText: 2025 XWiki CryptPad Team <contact@cryptpad.org> and Iulian-Tudor Scutaru
//
// SPDX-License-Identifier: AGPL-3.0-or-later

export const MODES = {
    SIMULATION: 'simulation',
    BENCHMARK: 'benchmark'
};

export class ModeSelector {
    constructor(onModeChange) {
        this.currentMode = MODES.SIMULATION;
        this.onModeChange = onModeChange;
        this.panel = null;
        this.toggleButton = null;
        this.isOpen = false;
        
        this.setupPanel();
    }

    setupPanel() {
        const modePanel = document.createElement('div');
        modePanel.className = 'mode-panel';
        modePanel.id = 'mode-panel';

        const toggleButton = document.createElement('button');
        toggleButton.className = 'mode-toggle-button';
        toggleButton.setAttribute('aria-label', 'Toggle mode selector');
        toggleButton.textContent = '[M]';
        
        toggleButton.addEventListener('click', () => this.togglePanel());
        document.body.appendChild(toggleButton);
        this.toggleButton = toggleButton;

        const panelContent = document.createElement('div');
        panelContent.className = 'mode-panel-content';

        const header = document.createElement('div');
        header.className = 'mode-panel-header';
        
        const title = document.createElement('h2');
        title.textContent = 'Select Mode';
        header.appendChild(title);

        const closeButton = document.createElement('button');
        closeButton.className = 'mode-panel-close';
        closeButton.setAttribute('aria-label', 'Close mode selector');
        closeButton.textContent = 'X';
        closeButton.addEventListener('click', () => this.closePanel());
        header.appendChild(closeButton);

        panelContent.appendChild(header);

        const modeOptions = document.createElement('div');
        modeOptions.className = 'mode-options';

        Object.values(MODES).forEach(mode => {
            const option = document.createElement('button');
            option.className = `mode-option ${mode === this.currentMode ? 'active' : ''}`;
            option.dataset.mode = mode;
            
            const modeConfig = this.getModeConfig(mode);
            option.innerHTML = `
                <div class="mode-option-label">${modeConfig.label}</div>
                <div class="mode-option-content">
                    <div class="mode-option-title">${modeConfig.title}</div>
                    <div class="mode-option-description">${modeConfig.description}</div>
                </div>
            `;

            option.addEventListener('click', () => this.selectMode(mode));
            modeOptions.appendChild(option);
        });

        panelContent.appendChild(modeOptions);
        modePanel.appendChild(panelContent);
        document.body.appendChild(modePanel);
        this.panel = modePanel;

        document.addEventListener('click', (e) => {
            if (!this.panel.contains(e.target) && e.target !== this.toggleButton) {
                this.closePanel();
            }
        });
    }

    getModeConfig(mode) {
        const configs = {
            [MODES.SIMULATION]: {
                label: 'SIM',
                title: 'Simulation Mode',
                description: 'Multi-user document collaboration with various cryptographic schemes'
            },
            [MODES.BENCHMARK]: {
                label: 'BENCH',
                title: 'Benchmark Mode',
                description: 'Performance testing of handshakes under different network conditions'
            }
        };
        return configs[mode];
    }

    selectMode(mode) {
        if (this.currentMode === mode) {
            this.closePanel();
            return;
        }

        this.currentMode = mode;
        
        const options = this.panel.querySelectorAll('.mode-option');
        options.forEach(opt => {
            opt.classList.toggle('active', opt.dataset.mode === mode);
        });

        this.onModeChange(mode);
        this.closePanel();
    }

    togglePanel() {
        if (this.isOpen) {
            this.closePanel();
        } else {
            this.openPanel();
        }
    }

    openPanel() {
        this.isOpen = true;
        this.panel.classList.add('open');
        this.toggleButton.classList.add('open');
        document.body.style.overflow = 'hidden';
    }

    closePanel() {
        this.isOpen = false;
        this.panel.classList.remove('open');
        this.toggleButton.classList.remove('open');
        document.body.style.overflow = '';
    }

    getMode() {
        return this.currentMode;
    }
}
