import React, { useState } from 'react';
import { X, ShieldAlert, AlertTriangle, CheckCircle, Activity, ChevronRight, ChevronLeft, Clock, User, MapPin, Target, Maximize2, Minimize2 } from 'lucide-react';

export default function InvestigationSummary({ summary, onClose }) {


    // Column widths for resizable timeline table
    const [columnWidths, setColumnWidths] = useState({
        step: 50,
        when: 120,
        who: 300,
        what: 200,
        where: 250
    });

    if (!summary) return null;

    const { narrative, remediation_steps, metrics, timeline } = summary;

    // Internal collapse state removed in favor of parent control
    // if (isCollapsed) { ... }

    // Column resize handler
    const handleMouseDown = (column) => (e) => {
        e.preventDefault();
        const startX = e.pageX;
        const startWidth = columnWidths[column];

        const handleMouseMove = (e) => {
            const diff = e.pageX - startX;
            setColumnWidths(prev => ({
                ...prev,
                [column]: Math.max(50, startWidth + diff)
            }));
        };

        const handleMouseUp = () => {
            document.removeEventListener('mousemove', handleMouseMove);
            document.removeEventListener('mouseup', handleMouseUp);
        };

        document.addEventListener('mousemove', handleMouseMove);
        document.addEventListener('mouseup', handleMouseUp);
    };

    return (
        <div
            style={{
                width: '100%',
                height: '100%',
                overflowY: 'auto',
                padding: '20px',
                background: 'transparent'
            }}
        >
            {/* Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <ShieldAlert color="#00f3ff" size={24} />
                    <h3 style={{ margin: 0, fontSize: '1.1rem', textTransform: 'uppercase', letterSpacing: '1px' }}>
                        Investigation Summary
                    </h3>
                </div>
                <div style={{ display: 'flex', gap: '8px' }}>
                    <button
                        className="btn-ghost btn-sm"
                        onClick={onClose}
                        title="Close"
                    >
                        <X size={18} />
                    </button>
                </div>
            </div>

            {/* Metrics */}
            <div style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(3, 1fr)',
                gap: '10px',
                marginBottom: '20px',
                padding: '10px',
                background: 'rgba(0, 243, 255, 0.05)',
                borderRadius: '8px',
                border: '1px solid rgba(0, 243, 255, 0.2)'
            }}>
                <div>
                    <div style={{ fontSize: '0.7rem', color: '#888', textTransform: 'uppercase' }}>Total Alerts</div>
                    <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#00f3ff' }}>{metrics.total_alerts}</div>
                </div>
                <div>
                    <div style={{ fontSize: '0.7rem', color: '#888', textTransform: 'uppercase' }}>Security Events</div>
                    <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#ff0055' }}>{metrics.security_alerts}</div>
                </div>
                <div>
                    <div style={{ fontSize: '0.7rem', color: '#888', textTransform: 'uppercase' }}>Tactics</div>
                    <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#ffcc00' }}>{metrics.tactics_involved.length}</div>
                </div>
            </div>

            {/* Severity Breakdown */}
            {metrics.severity_breakdown && Object.keys(metrics.severity_breakdown).length > 0 && (
                <div style={{ marginBottom: '20px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '5px', marginBottom: '8px' }}>
                        <AlertTriangle size={14} color="#ffcc00" />
                        <h4 style={{ margin: 0, fontSize: '0.85rem', textTransform: 'uppercase', color: '#ffcc00' }}>
                            Severity Breakdown
                        </h4>
                    </div>
                    <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                        {Object.entries(metrics.severity_breakdown).map(([severity, count]) => (
                            <div
                                key={severity}
                                style={{
                                    padding: '5px 12px',
                                    borderRadius: '12px',
                                    fontSize: '0.75rem',
                                    background: severity === 'Critical' ? 'rgba(255, 0, 85, 0.2)' :
                                        severity === 'High' ? 'rgba(255, 165, 0, 0.2)' :
                                            'rgba(255, 204, 0, 0.2)',
                                    border: `1px solid ${severity === 'Critical' ? '#ff0055' :
                                        severity === 'High' ? '#ffa500' :
                                            '#ffcc00'}`,
                                    color: severity === 'Critical' ? '#ff0055' :
                                        severity === 'High' ? '#ffa500' :
                                            '#ffcc00'
                                }}
                            >
                                {severity}: {count}
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Correlation Analysis (New Structured Summary) */}
            <div style={{ marginBottom: '20px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '5px', marginBottom: '8px' }}>
                    <Activity size={14} color="#00f3ff" />
                    <h4 style={{ margin: 0, fontSize: '0.85rem', textTransform: 'uppercase', color: '#00f3ff' }}>
                        Correlation Analysis
                    </h4>
                </div>
                <div style={{
                    fontSize: '0.85rem',
                    lineHeight: '1.6',
                    color: '#ccc',
                    padding: '15px',
                    background: 'rgba(255, 255, 255, 0.02)',
                    borderRadius: '6px',
                    border: '1px solid rgba(255, 255, 255, 0.1)'
                }}>

                    {/* Summary Section */}
                    <div style={{ marginBottom: '15px' }}>
                        <h5 style={{ margin: '0 0 5px 0', fontSize: '0.9rem', color: '#fff', fontWeight: 'bold' }}>Summary:</h5>
                        <p style={{ margin: 0, color: '#ccc' }}>
                            {summary.correlation_analysis?.summary || narrative}
                        </p>
                    </div>

                    {/* Impact Section */}
                    {summary.correlation_analysis?.impact && (
                        <div style={{ marginBottom: '15px' }}>
                            <h5 style={{ margin: '0 0 5px 0', fontSize: '0.9rem', color: '#fff', fontWeight: 'bold' }}>Impact:</h5>
                            <p style={{ margin: 0, color: '#ccc' }}>
                                {summary.correlation_analysis.impact}
                            </p>
                        </div>
                    )}

                    {/* Mitigation Section (Contextual) */}
                    {summary.correlation_analysis?.mitigation && (
                        <div style={{ marginBottom: '15px' }}>
                            <h5 style={{ margin: '0 0 5px 0', fontSize: '0.9rem', color: '#fff', fontWeight: 'bold' }}>Mitigation:</h5>
                            <p style={{ margin: 0, color: '#ccc' }}>
                                {summary.correlation_analysis.mitigation}
                            </p>
                        </div>
                    )}

                    {/* MITRE Tactic and Technique */}
                    {summary.correlation_analysis?.mitre_technique && summary.correlation_analysis.mitre_technique.length > 0 && (
                        <div>
                            <h5 style={{ margin: '0 0 5px 0', fontSize: '0.9rem', color: '#fff', fontWeight: 'bold' }}>MITRE Tactic and Technique:</h5>
                            <ul style={{ margin: 0, paddingLeft: '20px', color: '#ccc' }}>
                                {summary.correlation_analysis.mitre_technique.map((item, idx) => (
                                    <li key={idx}>
                                        <span style={{ color: '#00f3ff' }}>{item.tactic}</span>: {item.technique}
                                    </li>
                                ))}
                            </ul>
                        </div>
                    )}
                </div>
            </div>

            {/* Timeline Table with Resizable Columns */}
            {timeline && timeline.length > 0 && (
                <div style={{ marginBottom: '20px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '5px', marginBottom: '8px' }}>
                        <Clock size={14} color="#ff9900" />
                        <h4 style={{ margin: 0, fontSize: '0.85rem', textTransform: 'uppercase', color: '#ff9900' }}>
                            Attack Timeline (Drag column edges to resize)
                        </h4>
                    </div>
                    <div style={{
                        background: 'rgba(0, 0, 0, 0.3)',
                        borderRadius: '6px',
                        border: '1px solid rgba(255, 153, 0, 0.2)',
                        overflow: 'auto',
                        maxHeight: '400px'
                    }}>
                        <table style={{
                            width: '100%',
                            borderCollapse: 'collapse',
                            tableLayout: 'fixed'
                        }}>
                            <thead style={{
                                position: 'sticky',
                                top: 0,
                                background: 'rgba(255, 153, 0, 0.1)',
                                zIndex: 1
                            }}>
                                <tr>
                                    <th style={{
                                        width: `${columnWidths.step}px`,
                                        padding: '8px',
                                        borderBottom: '1px solid rgba(255, 153, 0, 0.3)',
                                        fontSize: '0.7rem',
                                        fontWeight: 'bold',
                                        textTransform: 'uppercase',
                                        color: '#ff9900',
                                        textAlign: 'left',
                                        position: 'relative',
                                        userSelect: 'none'
                                    }}>
                                        #
                                        <div
                                            onMouseDown={handleMouseDown('step')}
                                            style={{
                                                position: 'absolute',
                                                right: 0,
                                                top: 0,
                                                bottom: 0,
                                                width: '4px',
                                                cursor: 'col-resize',
                                                background: 'transparent',
                                                '&:hover': { background: '#ff9900' }
                                            }}
                                        />
                                    </th>
                                    <th style={{
                                        width: `${columnWidths.when}px`,
                                        padding: '8px',
                                        borderBottom: '1px solid rgba(255, 153, 0, 0.3)',
                                        fontSize: '0.7rem',
                                        fontWeight: 'bold',
                                        textTransform: 'uppercase',
                                        color: '#ff9900',
                                        textAlign: 'left',
                                        position: 'relative',
                                        userSelect: 'none'
                                    }}>
                                        When
                                        <div
                                            onMouseDown={handleMouseDown('when')}
                                            style={{
                                                position: 'absolute',
                                                right: 0,
                                                top: 0,
                                                bottom: 0,
                                                width: '4px',
                                                cursor: 'col-resize',
                                                background: 'transparent'
                                            }}
                                        />
                                    </th>
                                    <th style={{
                                        width: `${columnWidths.who}px`,
                                        padding: '8px',
                                        borderBottom: '1px solid rgba(255, 153, 0, 0.3)',
                                        fontSize: '0.7rem',
                                        fontWeight: 'bold',
                                        textTransform: 'uppercase',
                                        color: '#ff9900',
                                        textAlign: 'left',
                                        position: 'relative',
                                        userSelect: 'none'
                                    }}>
                                        Who (Source)
                                        <div
                                            onMouseDown={handleMouseDown('who')}
                                            style={{
                                                position: 'absolute',
                                                right: 0,
                                                top: 0,
                                                bottom: 0,
                                                width: '4px',
                                                cursor: 'col-resize',
                                                background: 'transparent'
                                            }}
                                        />
                                    </th>
                                    <th style={{
                                        width: `${columnWidths.what}px`,
                                        padding: '8px',
                                        borderBottom: '1px solid rgba(255, 153, 0, 0.3)',
                                        fontSize: '0.7rem',
                                        fontWeight: 'bold',
                                        textTransform: 'uppercase',
                                        color: '#ff9900',
                                        textAlign: 'left',
                                        position: 'relative',
                                        userSelect: 'none'
                                    }}>
                                        What
                                        <div
                                            onMouseDown={handleMouseDown('what')}
                                            style={{
                                                position: 'absolute',
                                                right: 0,
                                                top: 0,
                                                bottom: 0,
                                                width: '4px',
                                                cursor: 'col-resize',
                                                background: 'transparent'
                                            }}
                                        />
                                    </th>
                                    <th style={{
                                        width: `${columnWidths.where}px`,
                                        padding: '8px',
                                        borderBottom: '1px solid rgba(255, 153, 0, 0.3)',
                                        fontSize: '0.7rem',
                                        fontWeight: 'bold',
                                        textTransform: 'uppercase',
                                        color: '#ff9900',
                                        textAlign: 'left',
                                        userSelect: 'none'
                                    }}>
                                        Where (Target)
                                    </th>
                                </tr>
                            </thead>
                            <tbody>
                                {timeline.map((event, index) => (
                                    <tr key={index} style={{
                                        background: event.severity === 'Critical' ? 'rgba(255, 0, 85, 0.05)' :
                                            event.severity === 'High' ? 'rgba(255, 165, 0, 0.05)' : 'transparent'
                                    }}>
                                        <td style={{
                                            padding: '8px',
                                            borderBottom: index < timeline.length - 1 ? '1px solid rgba(255, 255, 255, 0.05)' : 'none',
                                            color: '#ff9900',
                                            fontWeight: 'bold',
                                            fontSize: '0.9rem'
                                        }}>
                                            {event.step || index + 1}
                                        </td>
                                        <td style={{
                                            padding: '8px',
                                            borderBottom: index < timeline.length - 1 ? '1px solid rgba(255, 255, 255, 0.05)' : 'none',
                                            color: '#aaa',
                                            fontSize: '0.7rem',
                                            fontFamily: 'monospace'
                                        }}>
                                            {new Date(event.when).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                                        </td>
                                        <td style={{
                                            padding: '8px',
                                            borderBottom: index < timeline.length - 1 ? '1px solid rgba(255, 255, 255, 0.05)' : 'none',
                                            color: '#00f3ff',
                                            fontSize: '0.75rem',
                                            wordBreak: 'break-word'
                                        }}>
                                            {event.who}
                                        </td>
                                        <td style={{
                                            padding: '8px',
                                            borderBottom: index < timeline.length - 1 ? '1px solid rgba(255, 255, 255, 0.05)' : 'none',
                                            color: '#fff',
                                            fontWeight: '500',
                                            fontSize: '0.75rem',
                                            wordBreak: 'break-word'
                                        }}>
                                            {event.what}
                                        </td>
                                        <td style={{
                                            padding: '8px',
                                            borderBottom: index < timeline.length - 1 ? '1px solid rgba(255, 255, 255, 0.05)' : 'none',
                                            color: '#ffcc00',
                                            fontSize: '0.75rem',
                                            wordBreak: 'break-word'
                                        }}>
                                            {event.where}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}

            {/* Remediation Steps */}
            {remediation_steps && remediation_steps.length > 0 && (
                <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '5px', marginBottom: '8px' }}>
                        <CheckCircle size={14} color="#00ff88" />
                        <h4 style={{ margin: 0, fontSize: '0.85rem', textTransform: 'uppercase', color: '#00ff88' }}>
                            Recommended Actions
                        </h4>
                    </div>
                    <div style={{
                        padding: '12px',
                        background: 'rgba(0, 255, 136, 0.05)',
                        borderRadius: '6px',
                        border: '1px solid rgba(0, 255, 136, 0.2)'
                    }}>
                        {remediation_steps.map((step, index) => (
                            <div
                                key={index}
                                style={{
                                    fontSize: '0.8rem',
                                    lineHeight: '1.5',
                                    color: '#ddd',
                                    marginBottom: index < remediation_steps.length - 1 ? '8px' : 0,
                                    paddingBottom: index < remediation_steps.length - 1 ? '8px' : 0,
                                    borderBottom: index < remediation_steps.length - 1 ? '1px solid rgba(255, 255, 255, 0.05)' : 'none'
                                }}
                            >
                                {step}
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
}
