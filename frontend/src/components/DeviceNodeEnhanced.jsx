import React from 'react';
import { Handle, Position } from 'reactflow';
import {
    ShieldAlert, Server, Database, Activity, Globe, Lock,
    Wifi, HardDrive, Cloud, Network, User, Terminal, AlertTriangle
} from 'lucide-react';

const iconMap = {
    'Internet': Globe,
    'Firewall': ShieldAlert,
    'Server': Server,
    'Database': Database,
    'Auth': Lock,
    'Workstation': Terminal,
    'Network': Wifi,
    'Cloud': Cloud,
    'Activity': Activity,
    'User': User,
    'Storage': HardDrive,
    'default': Network
};

// Extract probability from label (e.g., "Collection (60%)")
const extractProbability = (label) => {
    const match = label.match(/\((\d+)%\)/);
    return match ? parseInt(match[1]) : 0;
};

// Check if tactic is critical
const isCriticalTactic = (label) => {
    const labelLower = label.toLowerCase();
    return (
        labelLower.includes('exfiltration') ||
        labelLower.includes('impact') ||
        labelLower.includes('collection') ||
        labelLower.includes('credential access')
    );
};

// Severity logic mapper based on MITRE ATT&CK kill chain progression
const getSeverityLevel = (label, status) => {
    const probability = extractProbability(label);

    // For predicted nodes - color based ONLY on probability
    if (probability > 0 || status === 'target' || status === 'predicted') {
        // High probability (>=50%) -> RED
        if (probability >= 50) {
            return 'predicted-high';
        }
        // Medium probability (20-50%) -> YELLOW
        else if (probability >= 20) {
            return 'predicted-medium';
        }
        // Low probability (<20%) -> GRAY
        else {
            return 'predicted-low';
        }
    }

    const labelLower = label.toLowerCase();

    // CRITICAL (Stage 3) - Final stages / Crown Jewels
    if (
        labelLower.includes('exfiltration') ||
        labelLower.includes('impact') ||
        labelLower.includes('collection') ||
        labelLower.includes('credential access') ||
        labelLower.includes('crown jewel')
    ) {
        return 'critical';
    }

    // MEDIUM (Stage 2) - Active operations
    if (
        labelLower.includes('persistence') ||
        labelLower.includes('privilege escalation') ||
        labelLower.includes('defense evasion') ||
        labelLower.includes('lateral movement') ||
        labelLower.includes('command and control') ||
        labelLower.includes('execution')
    ) {
        return 'medium';
    }

    // LOW (Stage 1) - Reconnaissance / Initial Access
    return 'low';
};

// Severity-based styling configuration
const severityStyles = {
    low: {
        borderColor: 'rgb(6, 182, 212)',
        glowColor: 'rgba(6, 182, 212, 0.4)',
        shadowIntensity: '0 0 8px',
        bgGradient: 'radial-gradient(circle at top left, rgba(6, 182, 212, 0.03), transparent)',
        pulseAnimation: false,
        label: 'Stealth Mode',
        labelColor: '#06b6d4'
    },
    medium: {
        borderColor: 'rgb(245, 158, 11)',
        glowColor: 'rgba(245, 158, 11, 0.5)',
        shadowIntensity: '0 0 16px',
        bgGradient: 'radial-gradient(circle at top left, rgba(245, 158, 11, 0.05), transparent)',
        pulseAnimation: false,
        label: 'Active Threat',
        labelColor: '#f59e0b'
    },
    critical: {
        borderColor: 'rgb(244, 63, 94)',
        glowColor: 'rgba(244, 63, 94, 0.6)',
        shadowIntensity: '0 0 24px',
        bgGradient: 'radial-gradient(circle at center, rgba(244, 63, 94, 0.15), rgba(244, 63, 94, 0.05), transparent)',
        pulseAnimation: true,
        label: 'BREACH MODE',
        labelColor: '#f43f5e'
    },
    // High-probability predicted (>=50%) - RED
    'predicted-high': {
        borderColor: 'rgb(239, 68, 68)',
        glowColor: 'rgba(239, 68, 68, 0.6)',
        shadowIntensity: '0 0 20px',
        bgGradient: 'radial-gradient(circle at center, rgba(239, 68, 68, 0.1), transparent)',
        pulseAnimation: true,
        labelColor: '#ef4444',
        dashed: true,
        borderWidth: '3px'
    },
    // Medium-probability predicted (20-50%) - YELLOW
    'predicted-medium': {
        borderColor: 'rgb(250, 204, 21)',
        glowColor: 'rgba(250, 204, 21, 0.4)',
        shadowIntensity: '0 0 12px',
        bgGradient: 'radial-gradient(circle at top left, rgba(250, 204, 21, 0.05), transparent)',
        pulseAnimation: false,
        labelColor: '#facc15',
        dashed: true,
        borderWidth: '2px'
    },
    // Low-probability predicted (<20%) - GRAY
    'predicted-low': {
        borderColor: 'rgb(156, 163, 175)',
        glowColor: 'rgba(156, 163, 175, 0.3)',
        shadowIntensity: '0 0 8px',
        bgGradient: 'radial-gradient(circle at top left, rgba(156, 163, 175, 0.03), transparent)',
        pulseAnimation: false,
        labelColor: '#9ca3af',
        dashed: true,
        borderWidth: '1px',
        opacity: 0.7
    }
};

export default function DeviceNodeEnhanced({ data, selected }) {
    const Icon = iconMap[data.icon] || iconMap.default;
    const severityLevel = getSeverityLevel(data.label, data.status);
    const style = severityStyles[severityLevel];
    const probability = extractProbability(data.label);
    const isCritical = isCriticalTactic(data.label);

    return (
        <>
            <Handle type="target" position={Position.Top} />

            <div
                className={`device-node-enhanced ${style.pulseAnimation ? 'pulse-border' : ''} ${selected ? 'node-selected' : ''}`}
                style={{
                    background: `linear-gradient(135deg, #0a0a0a 0%, #050505 100%), ${style.bgGradient}`,
                    border: `${style.borderWidth || '2px'} ${style.dashed ? 'dashed' : 'solid'} ${style.borderColor}`,
                    boxShadow: `${style.shadowIntensity} ${style.glowColor}, inset 0 0 20px rgba(0, 0, 0, 0.9)`,
                    minWidth: '180px',
                    padding: '12px 16px',
                    position: 'relative',
                    transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
                    transform: selected ? 'scale(1.05)' : 'scale(1)',
                    opacity: style.opacity || (style.dashed ? 0.85 : 1)
                }}
            >
                {/* Severity indicator badge - only show for confirmed attack stages */}
                {!probability && style.label && (
                    <div
                        className={style.pulseAnimation ? 'severity-badge' : ''}
                        style={{
                            position: 'absolute',
                            top: '-8px',
                            right: '12px',
                            background: style.borderColor,
                            color: '#000',
                            fontSize: '0.6rem',
                            fontWeight: 700,
                            padding: '2px 8px',
                            fontFamily: 'JetBrains Mono, monospace',
                            textTransform: 'uppercase',
                            letterSpacing: '0.5px',
                            boxShadow: `0 0 8px ${style.glowColor}`
                        }}
                    >
                        {style.label}
                    </div>
                )}

                {/* Critical tactic warning - only for predicted critical tactics */}
                {isCritical && probability > 0 && (
                    <div
                        style={{
                            position: 'absolute',
                            top: '-8px',
                            left: '12px',
                            background: '#ef4444',
                            padding: '2px 8px',
                            fontSize: '0.6rem',
                            fontWeight: 700,
                            fontFamily: 'JetBrains Mono, monospace',
                            textTransform: 'uppercase',
                            letterSpacing: '0.5px',
                            boxShadow: '0 0 12px rgba(239, 68, 68, 0.8)',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '4px'
                        }}
                    >
                        <AlertTriangle size={10} color="#000" />
                        <span style={{ color: '#000' }}>RISK</span>
                    </div>
                )}

                {/* Icon */}
                <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '12px',
                    marginBottom: '4px'
                }}>
                    <Icon
                        size={24}
                        color={style.borderColor}
                        style={{
                            filter: `drop-shadow(0 0 4px ${style.glowColor})`
                        }}
                    />

                    {/* Title */}
                    <div style={{ flex: 1 }}>
                        <div
                            style={{
                                fontSize: '0.9rem',
                                fontWeight: 700,
                                fontFamily: 'Rajdhani, sans-serif',
                                color: '#fff',
                                textTransform: 'uppercase',
                                letterSpacing: '0.5px',
                                textShadow: `0 0 8px ${style.glowColor}`,
                                lineHeight: 1.2
                            }}
                        >
                            {data.label}
                        </div>

                        {/* Tactic tag if present */}
                        {data.tactic && (
                            <div
                                style={{
                                    fontSize: '0.65rem',
                                    fontFamily: 'JetBrains Mono, monospace',
                                    color: style.labelColor,
                                    marginTop: '2px',
                                    opacity: 0.9
                                }}
                            >
                                {data.tactic}
                            </div>
                        )}

                        {/* Probability indicator for predicted nodes */}
                        {probability > 0 && (
                            <div style={{ marginTop: '4px' }}>
                                <div
                                    style={{
                                        fontSize: '0.65rem',
                                        fontFamily: 'JetBrains Mono, monospace',
                                        color: '#aaa',
                                        marginBottom: '2px'
                                    }}
                                >
                                    Probability
                                </div>
                                <div
                                    style={{
                                        width: '100%',
                                        height: '4px',
                                        background: 'rgba(255, 255, 255, 0.1)',
                                        borderRadius: '2px',
                                        overflow: 'hidden'
                                    }}
                                >
                                    <div
                                        style={{
                                            width: `${probability}%`,
                                            height: '100%',
                                            background: style.borderColor,
                                            boxShadow: `0 0 8px ${style.glowColor}`,
                                            transition: 'width 0.5s ease'
                                        }}
                                    />
                                </div>
                            </div>
                        )}
                    </div>
                </div>

                {/* Status indicator dot */}
                <div
                    className={style.pulseAnimation ? 'pulse-dot' : ''}
                    style={{
                        position: 'absolute',
                        bottom: '8px',
                        right: '8px',
                        width: '6px',
                        height: '6px',
                        borderRadius: '50%',
                        background: style.borderColor,
                        boxShadow: `0 0 8px ${style.glowColor}`
                    }}
                />

                {/* Glitch effect overlay for critical nodes */}
                {style.pulseAnimation && (
                    <div
                        className="glitch-overlay"
                        style={{
                            position: 'absolute',
                            top: 0,
                            left: 0,
                            right: 0,
                            bottom: 0,
                            pointerEvents: 'none',
                            opacity: 0.1,
                            background: `repeating-linear-gradient(
                0deg,
                transparent,
                transparent 2px,
                ${style.borderColor} 2px,
                ${style.borderColor} 4px
              )`,
                            animation: 'glitch 4s infinite'
                        }}
                    />
                )}
            </div>

            <Handle type="source" position={Position.Bottom} />
        </>
    );
}
