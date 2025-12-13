import React, { memo } from 'react';
import { Handle, Position } from 'reactflow';
import {
    Server,
    Database,
    Globe,
    ShieldCheck,
    Laptop,
    Activity,
    Router,
    Lock
} from 'lucide-react';

const DeviceNode = ({ data, selected }) => {
    // Determine Icon based on type
    const getIcon = () => {
        switch (data.icon) {
            case 'Internet': return <Globe size={40} />;
            case 'Firewall': return <ShieldCheck size={40} />;
            case 'Server': return <Server size={40} />;
            case 'Database': return <Database size={40} />;
            case 'Workstation': return <Laptop size={40} />;
            case 'Auth': return <Lock size={40} />;
            default: return <Activity size={40} />;
        }
    };

    const getStatusColor = () => {
        if (data.status === 'compromised') return '#ff0055'; // Red
        
        // For predicted nodes, use probability-based colors
        if (data.status === 'target') {
            // Extract probability from label (e.g., "Exfiltration (67%)")
            const match = data.label.match(/\((\d+)%\)/);
            const probability = match ? parseInt(match[1]) : 0;
            
            // Check if it's a critical tactic
            const labelLower = data.label.toLowerCase();
            const isCritical = (
                labelLower.includes('exfiltration') ||
                labelLower.includes('impact') ||
                labelLower.includes('collection') ||
                labelLower.includes('credential access')
            );
            
            // High probability (>=50%) or critical tactic -> RED
            if (probability >= 50 || isCritical) {
                return '#ef4444'; // Red
            }
            // Medium probability (20-50%) -> YELLOW
            else if (probability >= 20) {
                return '#facc15'; // Yellow
            }
            // Low probability (<20%) -> GRAY
            else {
                return '#9ca3af'; // Gray
            }
        }
        
        return '#00f3ff'; // Cyan (Safe/Default)
    };

    const color = getStatusColor();
    const isCompromised = data.status === 'compromised';

    return (
        <div className={`device-node ${selected ? 'selected' : ''}`} style={{
            padding: '10px',
            borderRadius: '0',
            background: 'rgba(10, 10, 20, 0.8)',
            border: `2px solid ${color}`,
            boxShadow: selected || isCompromised ? `0 0 15px ${color}` : 'none',
            color: color,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            minWidth: '100px',
            backdropFilter: 'blur(5px)',
            transition: 'all 0.3s ease',
            animation: isCompromised ? 'pulse-red 2s infinite' : 'none'
        }}>
            <Handle type="target" position={Position.Top} style={{ background: color }} />

            <div style={{ marginBottom: '5px' }}>
                {getIcon()}
            </div>

            <div style={{
                fontSize: '0.7rem',
                fontWeight: 'bold',
                textAlign: 'center',
                textTransform: 'uppercase',
                letterSpacing: '1px'
            }}>
                {data.label}
            </div>

            <Handle type="source" position={Position.Bottom} style={{ background: color }} />
        </div>
    );
};

export default memo(DeviceNode);
