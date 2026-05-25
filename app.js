/**
 * DoS/DDoS Simulation Engine & Dashboard Controller
 * Implements high-performance canvas topology rendering, custom line charts,
 * sliding-window Shannon Entropy calculator, iptables rules processor,
 * and state-machine representing system loads and threat alerts.
 */

// --- STATE MANAGEMENT ---
const state = {
    // Simulator states
    isSniffing: true,
    packetCount: 0,
    simTime: 0,
    
    // Traffic generator configuration
    legitRate: 20, // Legitimate packets/sec
    attackVector: 'none', // none, syn, udp, http
    attackRate: 500, // Attack packets/sec
    
    // Defensive Rules (Firewall)
    synCookies: false,
    rateLimiting: false,
    blockRules: [
        // { ip: '10.0.2.15', action: 'DROP', pkts: 0 } // sample rule
    ],

    // Active metrics
    totalPPS: 0,
    currentEntropy: 0.0,
    serverCPU: 0,
    socketCapacity: 0, // 0 to 100
    activeConnsCount: 0,
    
    // Historical arrays for charting
    history: {
        timestamps: [],
        legitPPS: [],
        attackPPS: [],
        cpu: []
    },
    
    // Sliding packet buffer for Wireshark & Entropy calc
    packetBuffer: [],
    maxBufferSize: 100,
    
    // Canvas Particles
    particles: []
};

// --- DOM ELEMENTS ---
const elements = {
    cleanRateVal: document.getElementById('clean-rate-val'),
    cleanTrafficRate: document.getElementById('clean-traffic-rate'),
    attackRateVal: document.getElementById('attack-rate-val'),
    attackTrafficRate: document.getElementById('attack-traffic-rate'),
    attackRateContainer: document.getElementById('attack-rate-container'),
    
    // Defenses
    toggleSynCookies: document.getElementById('toggle-syn-cookies'),
    toggleRateLimit: document.getElementById('toggle-rate-limit'),
    blockIpInput: document.getElementById('block-ip-input'),
    addBlockRuleBtn: document.getElementById('add-block-rule-btn'),
    iptablesRulesTable: document.getElementById('iptables-rules-table'),
    flushRulesBtn: document.getElementById('flush-rules-btn'),
    shieldBadgeState: document.getElementById('shield-badge-state'),
    
    // Network Canvas
    topologyCanvas: document.getElementById('topology-canvas'),
    
    // IDS
    riskBadge: document.getElementById('risk-badge'),
    idsTotalPps: document.getElementById('ids-total-pps'),
    idsEntropy: document.getElementById('ids-entropy'),
    entropyProfileLabel: document.getElementById('entropy-profile-label'),
    entropyFill: document.getElementById('entropy-fill'),
    idsAlertLog: document.getElementById('ids-alert-log'),
    
    // Server
    serverStatusBadge: document.getElementById('server-status-badge'),
    cpuGaugePath: document.getElementById('cpu-gauge-path'),
    cpuGaugeText: document.getElementById('cpu-gauge-text'),
    connGaugePath: document.getElementById('conn-gauge-path'),
    connGaugeText: document.getElementById('conn-gauge-text'),
    metricsChart: document.getElementById('metrics-chart'),
    globalStatusText: document.getElementById('global-status-text'),
    statusDot: document.querySelector('.status-dot'),
    
    // Wireshark
    toggleSniffBtn: document.getElementById('toggle-sniff-btn'),
    clearSniffBtn: document.getElementById('clear-sniff-btn'),
    packetConsole: document.getElementById('packet-console')
};

// --- CONSTANTS ---
const ATTACKER_IP = '10.0.2.15';
const SPOOFED_SUBNET = '203.0.113.';
const CLEAN_IPS = ['192.168.1.10', '192.168.1.11', '192.168.1.12', '192.168.1.15', '192.168.1.20', '192.168.1.45'];
const SERVER_IP = '192.168.1.254';

// --- INITIALIZE FIREWALL RULES ---
function renderFirewallRules() {
    const tbody = elements.iptablesRulesTable.querySelector('tbody');
    tbody.innerHTML = '';

    if (state.blockRules.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" style="text-align:center; color: var(--text-muted);">No active filter rules.</td></tr>`;
        return;
    }

    state.blockRules.forEach((rule, idx) => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><span class="action-drop">DROP</span></td>
            <td><span style="font-family: var(--font-mono)">s: ${rule.ip}</span></td>
            <td style="font-family: var(--font-mono)">${rule.pkts} pkts</td>
            <td><button class="rule-delete-btn" data-idx="${idx}">&times;</button></td>
        `;
        tbody.appendChild(tr);
    });

    // Wire up delete buttons
    tbody.querySelectorAll('.rule-delete-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const idx = parseInt(e.target.getAttribute('data-idx'));
            state.blockRules.splice(idx, 1);
            addAlert('INFO', 'iptables rule removed.');
            renderFirewallRules();
            updateShieldBadge();
        });
    });
}

function updateShieldBadge() {
    const activeRulesCount = state.blockRules.length + (state.synCookies ? 1 : 0) + (state.rateLimiting ? 1 : 0);
    if (activeRulesCount > 0) {
        elements.shieldBadgeState.textContent = `${activeRulesCount} RULES ACTIVE`;
        elements.shieldBadgeState.className = 'shield-badge mitigating';
    } else {
        elements.shieldBadgeState.textContent = 'IDS DISARMED';
        elements.shieldBadgeState.className = 'shield-badge';
    }
}

// --- ALERTS LOGGER ---
function addAlert(level, message) {
    const log = elements.idsAlertLog;
    const timeStr = new Date().toLocaleTimeString();
    
    // Clear placeholder
    const placeholder = log.querySelector('.alert-placeholder');
    if (placeholder) {
        log.innerHTML = '';
    }

    const typeClass = level === 'CRITICAL' ? 'critical' : (level === 'WARNING' ? 'warning' : '');
    const entry = document.createElement('div');
    entry.className = `alert-entry ${typeClass}`;
    entry.innerHTML = `<span style="color: var(--text-muted)">[${timeStr}]</span> <strong>${level}:</strong> ${message}`;
    
    log.insertBefore(entry, log.firstChild);
    
    // Cap log items
    if (log.children.length > 25) {
        log.removeChild(log.lastChild);
    }
}

// --- SHANNON ENTROPY CALCULATOR ---
function calculateEntropy() {
    if (state.packetBuffer.length === 0) return 0.0;
    
    const ipCounts = {};
    let total = 0;
    
    // Count occurrences in buffer (legitimate/attack packets that bypass or hit firewall)
    state.packetBuffer.forEach(pkt => {
        if (pkt.status !== 'dropped') { // Entropy of received traffic at interface
            ipCounts[pkt.src] = (ipCounts[pkt.src] || 0) + 1;
            total++;
        }
    });
    
    if (total === 0) return 0.0;
    
    let entropy = 0.0;
    for (const ip in ipCounts) {
        const p_x = ipCounts[ip] / total;
        entropy -= p_x * Math.log2(p_x);
    }
    
    return entropy;
}

// --- INTRUSION DETECTION SYSTEM LOGIC ---
function runIDSEngine() {
    const entropy = calculateEntropy();
    state.currentEntropy = entropy;
    
    elements.idsTotalPps.textContent = `${state.totalPPS} pps`;
    elements.idsEntropy.textContent = entropy.toFixed(3);
    
    // Calculate entropy gauge fill percentage (max entropy is around log2(number of distinct IPs))
    // We calibrate 0.0 to 4.0 range
    const fillPercent = Math.min(100, (entropy / 4.0) * 100);
    elements.entropyFill.style.width = `${fillPercent}%`;

    // Visual indicators based on entropy and rate
    let risk = 'LOW';
    let riskClass = 'badge';
    let profile = 'Legitimate Balance';
    let profileColor = 'var(--color-green)';
    
    if (state.totalPPS > 150) {
        if (entropy < 1.3) {
            risk = 'HIGH';
            riskClass = 'badge red-badge';
            profile = 'Focused DoS Attack';
            profileColor = 'var(--color-red)';
            
            // Generate alerts
            if (Math.random() < 0.2) {
                const offendingIP = getDominantIP();
                addAlert('CRITICAL', `Potential Single-Source DoS flood from ${offendingIP} (Entropy: ${entropy.toFixed(2)})`);
            }
        } else if (entropy > 3.0) {
            risk = 'CRITICAL';
            riskClass = 'badge red-badge';
            profile = 'Spoofed/Distributed DDoS';
            profileColor = 'var(--color-red)';
            
            if (Math.random() < 0.2) {
                addAlert('CRITICAL', `Distributed DDoS Traffic Anomaly. Multiple IP clusters (Entropy: ${entropy.toFixed(2)})`);
            }
        } else {
            risk = 'MEDIUM';
            riskClass = 'badge';
            profile = 'High Traffic Vol.';
            profileColor = 'var(--color-orange)';
            
            if (Math.random() < 0.1) {
                addAlert('WARNING', 'Sustained packet rates above average thresholds.');
            }
        }
    } else {
        if (state.totalPPS > 40 && entropy < 0.5) {
            risk = 'MEDIUM';
            profile = 'Focused Connection Request';
            profileColor = 'var(--color-orange)';
        }
    }

    elements.riskBadge.textContent = `RISK: ${risk}`;
    elements.riskBadge.className = riskClass;
    elements.entropyProfileLabel.textContent = profile;
    elements.entropyProfileLabel.style.color = profileColor;
}

function getDominantIP() {
    const ipCounts = {};
    state.packetBuffer.forEach(pkt => {
        if (pkt.status !== 'dropped') {
            ipCounts[pkt.src] = (ipCounts[pkt.src] || 0) + 1;
        }
    });
    let maxIP = 'Unknown';
    let maxVal = 0;
    for (const ip in ipCounts) {
        if (ipCounts[ip] > maxVal) {
            maxVal = ipCounts[ip];
            maxIP = ip;
        }
    }
    return maxIP;
}

// --- SERVER DIAGNOSTICS & SYSTEM STRESS ---
function updateServerDiagnostics() {
    // CPU load and Connection capacity simulation
    let targetCPU = 5; // Idle background load
    
    // Add load for legitimate traffic
    targetCPU += state.legitRate * 0.25;
    
    // Attack load calculation
    if (state.attackVector !== 'none') {
        const attackPPS = state.attackRate;
        
        if (state.attackVector === 'syn') {
            if (state.synCookies) {
                // SYN cookies on: minimizes queue load and drops CPU stress significantly
                targetCPU += attackPPS * 0.05;
                state.activeConnsCount = Math.max(5, state.activeConnsCount - 15);
            } else {
                // SYN cookies off: backlog queue fills immediately!
                state.activeConnsCount = Math.min(100, state.activeConnsCount + (attackPPS * 0.06));
                targetCPU += state.activeConnsCount * 0.9;
            }
        } else if (state.attackVector === 'udp') {
            // UDP Flood: CPU load is moderate, but bandwidth is choked
            let blockedRatio = getBlockedPacketsRatio('UDP');
            let passedPPS = attackPPS * (1 - blockedRatio);
            targetCPU += passedPPS * 0.08;
            state.activeConnsCount = Math.max(5, state.activeConnsCount - 2);
        } else if (state.attackVector === 'http') {
            // HTTP Flood: Very intensive, fills active threads
            let blockedRatio = getBlockedPacketsRatio('TCP');
            let passedPPS = attackPPS * (1 - blockedRatio);
            
            // Rate limiting checks
            if (state.rateLimiting) {
                passedPPS = Math.min(passedPPS, 40); // throttled
            }
            
            state.activeConnsCount = Math.min(100, state.activeConnsCount + (passedPPS * 0.8));
            targetCPU += passedPPS * 0.7 + state.activeConnsCount * 0.3;
        }
    } else {
        // Clear active sockets slowly if attack stops
        state.activeConnsCount = Math.max(state.legitRate * 0.2, state.activeConnsCount - 10);
    }
    
    // Bound calculations
    state.serverCPU = Math.min(100, Math.max(3, Math.round(targetCPU)));
    state.socketCapacity = Math.round(state.activeConnsCount);
    
    // Update circular gauges
    setGaugeValue(elements.cpuGaugePath, elements.cpuGaugeText, state.serverCPU, 'var(--color-red)');
    setGaugeValue(elements.connGaugePath, elements.connGaugeText, state.socketCapacity, 'var(--color-blue)');

    // System Status indicator
    if (state.serverCPU > 85) {
        elements.serverStatusBadge.textContent = 'CRITICAL / DOWN';
        elements.serverStatusBadge.className = 'badge red-badge';
        elements.globalStatusText.textContent = 'SYSTEM OVERLOAD: SERVICE CRITICAL';
        elements.globalStatusText.style.color = 'var(--color-red)';
        elements.statusDot.className = 'status-dot attacked';
    } else if (state.serverCPU > 45) {
        elements.serverStatusBadge.textContent = 'STRESSED / SLOW';
        elements.serverStatusBadge.className = 'badge';
        elements.globalStatusText.textContent = 'WARNING: HIGH RESOURCE SATURATION';
        elements.globalStatusText.style.color = 'var(--color-orange)';
        elements.statusDot.className = 'status-dot restricted';
    } else {
        elements.serverStatusBadge.textContent = 'ONLINE';
        elements.serverStatusBadge.className = 'badge green-badge';
        elements.globalStatusText.textContent = 'NETWORK SECURE';
        elements.globalStatusText.style.color = 'var(--color-green)';
        elements.statusDot.className = 'status-dot online';
    }
}

function getBlockedPacketsRatio(proto) {
    // Checks if the attacker IP is blocked
    let isBlocked = false;
    
    // Attacker IP or Spoofed IP matching
    state.blockRules.forEach(rule => {
        if (rule.ip === ATTACKER_IP || (state.attackVector === 'udp' && rule.ip.startsWith(SPOOFED_SUBNET))) {
            isBlocked = true;
        }
    });

    if (isBlocked) return 1.0;
    
    return 0.0;
}

function setGaugeValue(pathElement, textElement, value, color) {
    const perimeter = 100; // standard circle stroke boundary
    const strokeDash = (value / 100) * perimeter;
    pathElement.setAttribute('stroke-dasharray', `${strokeDash}, ${perimeter}`);
    textElement.textContent = `${value}%`;
    
    // Set color severity
    if (value > 85) {
        pathElement.setAttribute('stroke', 'var(--color-red)');
    } else if (value > 45) {
        pathElement.setAttribute('stroke', 'var(--color-orange)');
    } else {
        pathElement.setAttribute('stroke', color);
    }
}

// --- PARTICLE PHYSICS ENGINE & TOPOLOGY MAP ---
const canvas = elements.topologyCanvas;
const ctx = canvas.getContext('2d');

// Node coordinates
const nodes = {
    attacker: { x: 80, y: 125, label: 'Kali Linux VM', ip: ATTACKER_IP, pulse: 0, color: 'var(--color-red)' },
    legit: { x: 80, y: 50, label: 'Legit User Base', ip: 'Dynamic', pulse: 0, color: 'var(--color-green)' },
    firewall: { x: 300, y: 100, label: 'iptables Shield', ip: 'Firewall', angle: 0, color: 'var(--color-blue)' },
    server: { x: 500, y: 100, label: 'Web Server', ip: SERVER_IP, color: 'var(--color-green)' }
};

function resizeCanvas() {
    canvas.width = canvas.parentElement.clientWidth;
    canvas.height = canvas.parentElement.clientHeight;
    
    // Recalculate node horizontal offsets dynamically to make it responsive
    const w = canvas.width;
    const h = canvas.height;
    
    nodes.attacker.x = w * 0.15;
    nodes.attacker.y = h * 0.70;
    
    nodes.legit.x = w * 0.15;
    nodes.legit.y = h * 0.30;
    
    nodes.firewall.x = w * 0.50;
    nodes.firewall.y = h * 0.50;
    
    nodes.server.x = w * 0.82;
    nodes.server.y = h * 0.50;
}

window.addEventListener('resize', resizeCanvas);
setTimeout(resizeCanvas, 100);

class PacketParticle {
    constructor(srcNode, dstNode, type, ip, proto) {
        this.srcX = srcNode.x;
        this.srcY = srcNode.y;
        this.dstX = dstNode.x;
        this.dstY = dstNode.y;
        this.x = this.srcX;
        this.y = this.srcY;
        this.progress = 0;
        this.speed = type === 'attack' ? 0.04 + Math.random() * 0.03 : 0.015 + Math.random() * 0.01;
        this.type = type; // attack, legit
        this.ip = ip;
        this.proto = proto;
        this.size = type === 'attack' ? 4 : 5;
        
        // Block check at the firewall node (progress = 0.5 represents arriving at the firewall)
        this.isBlocked = false;
        this.hasFiredBlock = false;
        
        // Determine blocking
        if (type === 'attack') {
            // Check custom IP Drop Rules
            state.blockRules.forEach(rule => {
                if (rule.ip === this.ip || (proto === 'UDP' && rule.ip.startsWith(SPOOFED_SUBNET))) {
                    this.isBlocked = true;
                    rule.pkts++;
                }
            });
            
            // Check Rate limit Rule
            if (state.rateLimiting && Math.random() < 0.85) {
                this.isBlocked = true;
            }
        }
    }

    update() {
        this.progress += this.speed;
        
        // Handle path from source to firewall (first half)
        if (this.progress < 0.5) {
            let t = this.progress * 2; // Normalize to [0, 1]
            this.x = this.srcX + (this.dstX - this.srcX) * t;
            this.y = this.srcY + (this.dstY - this.srcY) * t;
        } 
        // Handle firewall interaction
        else if (this.progress >= 0.5 && this.progress < 1.0) {
            if (this.isBlocked) {
                if (!this.hasFiredBlock) {
                    this.hasFiredBlock = true;
                    // Spawn spark particles for visual packet dropping!
                    spawnBlockSparks(this.x, this.y, this.type === 'attack' ? 'var(--color-red)' : 'var(--color-green)');
                    pushWiresharkPacket(this.ip, SERVER_IP, this.proto, 'dropped');
                }
                // Stop rendering this particle
                return false;
            }
            
            // Second half: Firewall to Server
            let t = (this.progress - 0.5) * 2; // Normalize to [0, 1]
            let fw = nodes.firewall;
            let srv = nodes.server;
            this.x = fw.x + (srv.x - fw.x) * t;
            this.y = fw.y + (srv.y - fw.y) * t;
            
            if (!this.hasFiredBlock) {
                this.hasFiredBlock = true;
            }
        } 
        // Completed journey to server
        else {
            pushWiresharkPacket(this.ip, SERVER_IP, this.proto, 'received');
            return false; // delete
        }
        return true;
    }

    draw() {
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
        
        if (this.type === 'attack') {
            ctx.fillStyle = 'var(--color-red)';
            ctx.shadowColor = 'var(--color-red)';
        } else {
            ctx.fillStyle = 'var(--color-green)';
            ctx.shadowColor = 'var(--color-green)';
        }
        
        ctx.shadowBlur = 6;
        ctx.fill();
        ctx.shadowBlur = 0; // reset
    }
}

// Spark system
let sparks = [];
class Spark {
    constructor(x, y, color) {
        this.x = x;
        this.y = y;
        this.vx = (Math.random() - 0.5) * 4;
        this.vy = (Math.random() - 0.5) * 4;
        this.alpha = 1.0;
        this.color = color;
        this.decay = 0.05 + Math.random() * 0.04;
    }
    update() {
        this.x += this.vx;
        this.y += this.vy;
        this.alpha -= this.decay;
        return this.alpha > 0;
    }
    draw() {
        ctx.beginPath();
        ctx.arc(this.x, this.y, 2, 0, Math.PI * 2);
        ctx.fillStyle = this.color;
        ctx.globalAlpha = this.alpha;
        ctx.fill();
        ctx.globalAlpha = 1.0;
    }
}

function spawnBlockSparks(x, y, color) {
    for (let i = 0; i < 8; i++) {
        sparks.push(new Spark(x, y, color));
    }
}

function drawNetworkTopology() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    // Draw interconnect cables (glow)
    ctx.beginPath();
    ctx.moveTo(nodes.attacker.x, nodes.attacker.y);
    ctx.lineTo(nodes.firewall.x, nodes.firewall.y);
    ctx.lineTo(nodes.server.x, nodes.server.y);
    ctx.moveTo(nodes.legit.x, nodes.legit.y);
    ctx.lineTo(nodes.firewall.x, nodes.firewall.y);
    
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.03)';
    ctx.lineWidth = 4;
    ctx.stroke();
    
    // Node pulse updates
    nodes.attacker.pulse += 0.08;
    nodes.legit.pulse += 0.03;
    nodes.firewall.angle += 0.02;

    // --- DRAW PARTICLES ---
    state.particles = state.particles.filter(p => {
        let active = p.update();
        if (active) p.draw();
        return active;
    });

    sparks = sparks.filter(s => {
        let active = s.update();
        if (active) s.draw();
        return active;
    });

    // --- DRAW NODES ---
    // Attacker
    drawVMNode(nodes.attacker, state.attackVector !== 'none' ? 'var(--color-red)' : 'var(--text-muted)', state.attackVector !== 'none');
    
    // Legit client base
    drawVMNode(nodes.legit, 'var(--color-green)', true);
    
    // Firewall Node (Interactive Shield)
    drawFirewallShield(nodes.firewall);
    
    // Web Server Node
    let srvColor = 'var(--color-green)';
    if (state.serverCPU > 85) srvColor = 'var(--color-red)';
    else if (state.serverCPU > 45) srvColor = 'var(--color-orange)';
    drawVMNode(nodes.server, srvColor, true);
}

function drawVMNode(node, color, isPulsing) {
    ctx.beginPath();
    ctx.arc(node.x, node.y, 20, 0, Math.PI * 2);
    ctx.fillStyle = 'rgba(12, 14, 30, 0.9)';
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.shadowColor = color;
    ctx.shadowBlur = isPulsing ? 10 + Math.sin(node.pulse) * 4 : 0;
    ctx.fill();
    ctx.stroke();
    ctx.shadowBlur = 0;

    // Draw little inner square representing VM server core
    ctx.fillStyle = color;
    ctx.fillRect(node.x - 6, node.y - 6, 12, 12);

    // Labels
    ctx.fillStyle = 'var(--text-primary)';
    ctx.font = 'bold 11px var(--font-sans)';
    ctx.textAlign = 'center';
    ctx.fillText(node.label, node.x, node.y + 36);
    
    ctx.fillStyle = 'var(--text-muted)';
    ctx.font = '10px var(--font-mono)';
    ctx.fillText(node.ip, node.x, node.y + 48);
}

function drawFirewallShield(node) {
    const isMitigating = state.blockRules.length > 0 || state.synCookies || state.rateLimiting;
    const shieldColor = isMitigating ? 'var(--color-green)' : 'var(--color-blue)';
    
    ctx.beginPath();
    ctx.arc(node.x, node.y, 22, 0, Math.PI * 2);
    ctx.fillStyle = 'rgba(6, 7, 18, 0.95)';
    ctx.strokeStyle = shieldColor;
    ctx.lineWidth = 2.5;
    ctx.shadowColor = shieldColor;
    ctx.shadowBlur = isMitigating ? 8 : 2;
    ctx.fill();
    ctx.stroke();
    ctx.shadowBlur = 0;

    // Draw interactive rotating shield pattern
    ctx.beginPath();
    ctx.arc(node.x, node.y, 14, node.angle, node.angle + Math.PI * 0.6);
    ctx.strokeStyle = shieldColor;
    ctx.lineWidth = 2;
    ctx.stroke();

    ctx.beginPath();
    ctx.arc(node.x, node.y, 14, node.angle + Math.PI, node.angle + Math.PI * 1.6);
    ctx.strokeStyle = shieldColor;
    ctx.lineWidth = 2;
    ctx.stroke();

    // Node labels
    ctx.fillStyle = 'var(--text-primary)';
    ctx.font = 'bold 11px var(--font-sans)';
    ctx.textAlign = 'center';
    ctx.fillText(node.label, node.x, node.y + 36);
    
    ctx.fillStyle = isMitigating ? 'var(--color-green)' : 'var(--text-muted)';
    ctx.font = 'bold 9px var(--font-mono)';
    ctx.fillText(isMitigating ? 'FILTERING ACTIVE' : 'IDS SNIFFING', node.x, node.y + 48);
}

// Particle spawner ticker
setInterval(() => {
    if (!state.isSniffing) return;
    
    // Spawn legitimate client traffic
    // Map legit PPS to tick-generation chance
    const legitSpawnChance = state.legitRate / 10;
    for (let i = 0; i < legitSpawnChance; i++) {
        if (Math.random() < 0.3) {
            const randomIP = CLEAN_IPS[Math.floor(Math.random() * CLEAN_IPS.length)];
            const proto = Math.random() < 0.2 ? 'UDP' : (Math.random() < 0.15 ? 'ICMP' : 'TCP');
            state.particles.push(new PacketParticle(nodes.legit, nodes.firewall, 'legit', randomIP, proto));
        }
    }

    // Spawn Attack Traffic
    if (state.attackVector !== 'none') {
        const attackSpawnChance = state.attackRate / 30;
        for (let i = 0; i < attackSpawnChance; i++) {
            if (Math.random() < 0.6) {
                let srcIP = ATTACKER_IP;
                let proto = 'TCP';
                
                if (state.attackVector === 'udp') {
                    // Spoofed source IPs
                    srcIP = `${SPOOFED_SUBNET}${Math.floor(Math.random() * 253 + 1)}`;
                    proto = 'UDP';
                } else if (state.attackVector === 'syn') {
                    proto = 'TCP'; // TCP SYN flag
                } else if (state.attackVector === 'http') {
                    proto = 'TCP'; // HTTP request
                }

                state.particles.push(new PacketParticle(nodes.attacker, nodes.firewall, 'attack', srcIP, proto));
            }
        }
    }
}, 100);

// Animation Loop
function animateTopology() {
    drawNetworkTopology();
    requestAnimationFrame(animateTopology);
}
requestAnimationFrame(animateTopology);

// --- WIRESHARK SIMULATED SNIFFER CONSOLE ---
function pushWiresharkPacket(src, dst, proto, status) {
    if (!state.isSniffing) return;
    
    state.packetCount++;
    
    // Buffer addition for entropy
    state.packetBuffer.push({ src, dst, proto, status });
    if (state.packetBuffer.length > state.maxBufferSize) {
        state.packetBuffer.shift();
    }

    // Create terminal table rows
    const container = elements.packetConsole;
    const timeStr = (performance.now() / 1000).toFixed(4);
    
    // Create random details for Wireshark info
    let info = 'Standard Data Transfer';
    let len = Math.floor(Math.random() * 800 + 64);
    let rowClass = 'clean';

    if (src === ATTACKER_IP || src.startsWith(SPOOFED_SUBNET)) {
        if (state.attackVector === 'syn') {
            info = `[SYN] Seq=0 Win=1024 Len=0 <mss,sackOK,TS,nop,wscale>`;
            len = 64;
            rowClass = 'tcp-syn';
        } else if (state.attackVector === 'udp') {
            info = `UDP Packet. DstPort=${Math.floor(Math.random() * 3000 + 4000)}`;
            len = 512;
            rowClass = 'udp';
        } else if (state.attackVector === 'http') {
            info = `GET / HTTP/1.1 (Request Flood)`;
            len = 340;
            rowClass = 'http';
        }
    } else {
        if (proto === 'TCP') {
            info = `[ACK] Seq=145 Ack=2900 Win=65535 Len=0`;
            len = 54;
        } else if (proto === 'UDP') {
            info = `DNS Query: Standard A records lookups`;
            len = 78;
        } else {
            info = `ICMP Echo Request (ping)`;
            len = 98;
        }
    }

    if (status === 'dropped') {
        info = `⚠️ DROPPED: Rule blocked packet by firewall policy`;
        rowClass = 'dropped';
    }

    const row = document.createElement('div');
    row.className = `ws-row ${rowClass}`;
    row.innerHTML = `
        <span class="ws-col col-num">${state.packetCount}</span>
        <span class="ws-col col-time">${timeStr}</span>
        <span class="ws-col col-src">${src}</span>
        <span class="ws-col col-dst">${dst}</span>
        <span class="ws-col col-proto">${proto}</span>
        <span class="ws-col col-len">${len}</span>
        <span class="ws-col col-info">${info}</span>
    `;

    container.appendChild(row);
    
    // Autoscroll
    container.scrollTop = container.scrollHeight;

    // Cap printed DOM elements to prevent performance lag
    if (container.children.length > 60) {
        container.removeChild(container.firstChild);
    }
}

// --- LIGHTWEIGHT CANVAS REAL-TIME CHARTS ---
const chartCanvas = elements.metricsChart;
const chartCtx = chartCanvas.getContext('2d');

function resizeChartCanvas() {
    chartCanvas.width = chartCanvas.parentElement.clientWidth;
    chartCanvas.height = chartCanvas.parentElement.clientHeight;
}
window.addEventListener('resize', resizeChartCanvas);
setTimeout(resizeChartCanvas, 120);

function drawMetricsChart() {
    const w = chartCanvas.width;
    const h = chartCanvas.height;
    chartCtx.clearRect(0, 0, w, h);

    if (state.history.timestamps.length < 2) return;

    // Draw Gridlines
    chartCtx.beginPath();
    chartCtx.strokeStyle = 'rgba(255, 255, 255, 0.04)';
    chartCtx.lineWidth = 1;
    for (let i = 1; i < 4; i++) {
        let y = h - (h * (i / 4));
        chartCtx.moveTo(0, y);
        chartCtx.lineTo(w, y);
    }
    chartCtx.stroke();

    // Plot helper
    function plotLine(dataArray, strokeStyle, shadowColor) {
        chartCtx.beginPath();
        chartCtx.strokeStyle = strokeStyle;
        chartCtx.lineWidth = 2.0;
        
        const count = dataArray.length;
        const maxVal = 100; // Calibrated load percentage / rate max

        dataArray.forEach((val, idx) => {
            let x = (idx / (count - 1)) * w;
            // Map 0-100 values to screen coordinates
            let y = h - ((val / maxVal) * (h - 10)) - 5;
            
            if (idx === 0) {
                chartCtx.moveTo(x, y);
            } else {
                chartCtx.lineTo(x, y);
            }
        });

        if (shadowColor) {
            chartCtx.shadowColor = shadowColor;
            chartCtx.shadowBlur = 6;
        }
        chartCtx.stroke();
        chartCtx.shadowBlur = 0; // reset
    }

    // Normalized visual scales for rates
    const normClean = state.history.legitPPS.map(v => Math.min(100, (v / 100) * 100));
    const normAttack = state.history.attackPPS.map(v => Math.min(100, (v / 2000) * 100));
    const cpuLoad = state.history.cpu;

    // Plot Lines
    plotLine(normClean, 'var(--color-green)', 'var(--color-green)');
    plotLine(normAttack, 'var(--color-red)', 'var(--color-red)');
    plotLine(cpuLoad, 'var(--color-blue)', 'var(--color-blue)');

    // Legend on Canvas
    chartCtx.font = '9px var(--font-mono)';
    chartCtx.fillStyle = 'var(--text-muted)';
    chartCtx.textAlign = 'right';
    chartCtx.fillText('Clean PPS', w - 160, 12);
    chartCtx.fillStyle = 'var(--color-green)';
    chartCtx.fillRect(w - 150, 6, 8, 8);

    chartCtx.fillStyle = 'var(--text-muted)';
    chartCtx.fillText('Attack PPS', w - 85, 12);
    chartCtx.fillStyle = 'var(--color-red)';
    chartCtx.fillRect(w - 75, 6, 8, 8);

    chartCtx.fillStyle = 'var(--text-muted)';
    chartCtx.fillText('Server CPU', w - 10, 12);
    chartCtx.fillStyle = 'var(--color-blue)';
    chartCtx.fillRect(w - 2, 6, 8, 8);
}

// --- TICK ENGINE (1-Second Statistics Accumulator) ---
setInterval(() => {
    state.simTime++;
    
    // Compute current real-time packet rates (legitimate vs. attack)
    let cleanPPS = state.legitRate;
    let attackPPS = 0;
    
    if (state.attackVector !== 'none') {
        attackPPS = state.attackRate;
    }
    
    state.totalPPS = cleanPPS + attackPPS;
    
    // Add current rules context and server load to historical arrays
    state.history.timestamps.push(state.simTime);
    state.history.legitPPS.push(cleanPPS);
    state.history.attackPPS.push(attackPPS);
    state.history.cpu.push(state.serverCPU);
    
    // Keep sliding chart values size capped
    if (state.history.timestamps.length > 30) {
        state.history.timestamps.shift();
        state.history.legitPPS.shift();
        state.history.attackPPS.shift();
        state.history.cpu.shift();
    }
    
    // Run diagnostics
    runIDSEngine();
    updateServerDiagnostics();
    drawMetricsChart();
    renderFirewallRules();
}, 1000);

// --- INTERACTIVE EVENT BINDINGS ---

// Clean rate slider
elements.cleanTrafficRate.addEventListener('input', (e) => {
    state.legitRate = parseInt(e.target.value);
    elements.cleanRateVal.textContent = `${state.legitRate} PPS`;
});

// Attack rate slider
elements.attackTrafficRate.addEventListener('input', (e) => {
    state.attackRate = parseInt(e.target.value);
    elements.attackRateVal.textContent = `${state.attackRate} PPS`;
});

// Attack vector radio selector
document.querySelectorAll('input[name="attack-vector"]').forEach(radio => {
    radio.addEventListener('change', (e) => {
        state.attackVector = e.target.value;
        if (state.attackVector === 'none') {
            elements.attackRateContainer.style.display = 'none';
            addAlert('INFO', 'Simulation Mode: Disengaged traffic generator. Clean traffic state.');
        } else {
            elements.attackRateContainer.style.display = 'block';
            addAlert('WARNING', `Simulation Mode: Triggered ${state.attackVector.toUpperCase()} Flood attack vector.`);
        }
    });
});

// Defenses toggles
elements.toggleSynCookies.addEventListener('change', (e) => {
    state.synCookies = e.target.checked;
    const stateStr = state.synCookies ? 'ENABLED' : 'DISABLED';
    addAlert('INFO', `Linux Defense Command: sysctl -w net.ipv4.tcp_syncookies=${state.synCookies ? 1 : 0} (${stateStr})`);
    updateShieldBadge();
});

elements.toggleRateLimit.addEventListener('change', (e) => {
    state.rateLimiting = e.target.checked;
    const stateStr = state.rateLimiting ? 'ESTABLISHED' : 'REVOKED';
    addAlert('INFO', `Linux iptables Rule: Applied packet rate limiting for INPUT TCP requests (${stateStr})`);
    updateShieldBadge();
});

// Adding Drop IP Rule
elements.addBlockRuleBtn.addEventListener('click', () => {
    const ip = elements.blockIpInput.value.trim();
    
    // Simple validation
    const ipPattern = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    if (!ipPattern.test(ip) && !ip.endsWith('.')) {
        alert('Invalid IP address format. Format must match xxx.xxx.xxx.xxx');
        return;
    }
    
    // Check duplication
    const dup = state.blockRules.find(r => r.ip === ip);
    if (dup) {
        alert('This IP drop filter rule already exists in the tables.');
        return;
    }

    state.blockRules.push({ ip: ip, action: 'DROP', pkts: 0 });
    addAlert('WARNING', `iptables command: iptables -A INPUT -s ${ip} -j DROP added to firewall filter tables.`);
    elements.blockIpInput.value = '';
    renderFirewallRules();
    updateShieldBadge();
});

// Flush all rules
elements.flushRulesBtn.addEventListener('click', () => {
    state.blockRules = [];
    addAlert('INFO', 'iptables command: iptables -F INPUT. Flushed all filter policies.');
    renderFirewallRules();
    updateShieldBadge();
});

// Pause / resume sniffer
elements.toggleSniffBtn.addEventListener('click', () => {
    state.isSniffing = !state.isSniffing;
    if (state.isSniffing) {
        elements.toggleSniffBtn.textContent = 'PAUSE SNIFFING';
        elements.toggleSniffBtn.className = 'cyber-btn active-btn';
    } else {
        elements.toggleSniffBtn.textContent = 'RESUME SNIFFING';
        elements.toggleSniffBtn.className = 'cyber-btn';
    }
});

// Clear Wireshark terminal
elements.clearSniffBtn.addEventListener('click', () => {
    elements.packetConsole.innerHTML = '<div class="alert-placeholder">Wireshark terminal logs cleared. Sniffing interface...</div>';
});
