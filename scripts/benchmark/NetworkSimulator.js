// SPDX-FileCopyrightText: 2025 XWiki CryptPad Team <contact@cryptpad.org> and Iulian-Tudor Scutaru
//
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Network Simulator for benchmarking
 * 
 * Emulates different network conditions:
 * - High-Speed/Local: No delay, unlimited bandwidth
 * - Mobile/4G: 50ms latency, 10 Mbps bandwidth, 10ms jitter
 * - Mobile/3G: 100ms latency, 3 Mbps bandwidth, 25ms jitter
 * - Satellite: 600ms latency, 1 Mbps bandwidth, 50ms jitter
 * 
 */

export const NETWORK_PROFILES = {
    HIGH_SPEED: {
        name: 'High-Speed / Local',
        latency: 0,           // ms - base latency
        bandwidth: Infinity,  // bytes/ms - effectively unlimited
        jitter: 0,           // ms - latency variation
        packetLoss: 0        // probability (0-1)
    },
    MOBILE_4G: {
        name: 'Mobile / 4G',
        latency: 50,         // ms - typical 4G latency
        bandwidth: 1250,     // bytes/ms = 10 Mbps (10 Megabits = 1.25 Megabytes)
        jitter: 10,          // ms - latency variation
        packetLoss: 0.001    // 0.1% packet loss
    },
    MOBILE_3G: {
        name: 'Mobile / 3G',
        latency: 100,        // ms
        bandwidth: 375,      // bytes/ms = 3 Mbps
        jitter: 25,          // ms
        packetLoss: 0.01     // 1% packet loss
    },
    SATELLITE: {
        name: 'Satellite',
        latency: 600,        // ms - geostationary orbit
        bandwidth: 125,      // bytes/ms = 1 Mbps
        jitter: 50,          // ms
        packetLoss: 0.02     // 2% packet loss
    }
};

export class NetworkSimulator {
    constructor(profile = NETWORK_PROFILES.HIGH_SPEED) {
        this.profile = profile;
        this.simulateDelay = profile.latency > 0 || profile.bandwidth < Infinity;
    }

    /**
     * Simulate network transmission delay
     * @param {number} payloadSize - Size of payload in bytes
     * @returns {Promise<number>} - Actual delay in milliseconds
     */
    async simulateTransmission(payloadSize) {
        // High-speed network: no delay
        if (!this.simulateDelay) {
            return 0;
        }

        // Calculate transmission time based on bandwidth
        const transmissionTime = this.profile.bandwidth === Infinity 
            ? 0 
            : payloadSize / this.profile.bandwidth;

        // Add base latency
        let totalDelay = this.profile.latency + transmissionTime;

        // Add jitter (random variation in latency)
        if (this.profile.jitter > 0) {
            const jitterValue = (Math.random() - 0.5) * 2 * this.profile.jitter;
            totalDelay += jitterValue;
        }

        // Simulate packet loss (requires retransmission)
        if (this.profile.packetLoss > 0 && Math.random() < this.profile.packetLoss) {
            // Simple retransmission: double the delay
            totalDelay *= 2;
        }

        // Ensure delay is non-negative
        totalDelay = Math.max(0, totalDelay);

        // For benchmarking, calculate delays but don't actually wait
        // This prevents browser event loop saturation during high-iteration tests
        // The calculated delay is still tracked for network impact analysis
        return totalDelay;
    }
    
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    calculateTransmissionTime(payloadSize) {
        if (this.profile.bandwidth === Infinity) {
            return this.profile.latency;
        }
        
        const transmissionTime = payloadSize / this.profile.bandwidth;
        return this.profile.latency + transmissionTime;
    }

    getProfileInfo() {
        return {
            name: this.profile.name,
            latency: this.profile.latency,
            bandwidth: this.profile.bandwidth === Infinity 
                ? '∞' 
                : `${(this.profile.bandwidth * 8 / 1000).toFixed(2)} Mbps`,
            jitter: this.profile.jitter,
            packetLoss: `${(this.profile.packetLoss * 100).toFixed(2)}%`
        };
    }
}

export function compareNetworkProfiles(payloadSize = 2000) {
    console.log('\n=== Network Profile Comparison ===');
    console.log(`Payload Size: ${payloadSize} bytes\n`);
    
    Object.values(NETWORK_PROFILES).forEach(profile => {
        const sim = new NetworkSimulator(profile);
        const time = sim.calculateTransmissionTime(payloadSize);
        const info = sim.getProfileInfo();
        
        console.log(`${info.name}:`);
        console.log(`  Base Latency: ${info.latency}ms`);
        console.log(`  Bandwidth: ${info.bandwidth}`);
        console.log(`  Jitter: ±${info.jitter}ms`);
        console.log(`  Packet Loss: ${info.packetLoss}`);
        console.log(`  Transmission Time: ${time.toFixed(2)}ms`);
        console.log('');
    });
}
