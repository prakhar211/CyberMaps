import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion'; // eslint-disable-line no-unused-vars
import { X, Search, Shield, Database, AlertTriangle } from 'lucide-react';
import CodeBlock from './CodeBlock';

/**
 * PredictionDrawer - Right-side slide-out panel for predicted node intelligence
 * @param {Object} predictionData - Data object containing tactic, queries, rules, and IOCs
 * @param {boolean} isOpen - Whether the drawer is open
 * @param {Function} onClose - Callback to close the drawer
 */
export default function PredictionDrawer({ predictionData, isOpen, onClose }) {
    const [activeTab, setActiveTab] = useState('hunting');

    if (!predictionData) return null;

    const tabs = [
        { id: 'hunting', label: 'Threat Hunting', icon: Search },
        { id: 'rules', label: 'Detection Rules', icon: Shield },
        { id: 'iocs', label: 'Context IOCs', icon: Database }
    ];

    return (
        <AnimatePresence>
            {isOpen && (
                <>
                    {/* Backdrop */}
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="drawer-backdrop"
                        onClick={onClose}
                    />

                    {/* Drawer */}
                    <motion.div
                        initial={{ x: '100%' }}
                        animate={{ x: 0 }}
                        exit={{ x: '100%' }}
                        transition={{ type: 'spring', damping: 25, stiffness: 200 }}
                        className="prediction-drawer"
                    >
                        {/* Header */}
                        <div className="drawer-header">
                            <div className="drawer-header-content">
                                <AlertTriangle size={24} color="#facc15" />
                                <div>
                                    <h2 className="drawer-title">Predicted Attack Vector</h2>
                                    <div className="drawer-subtitle">
                                        {predictionData.tactic}
                                        <span className="probability-badge">
                                            {predictionData.probability} probability
                                        </span>
                                    </div>
                                </div>
                            </div>
                            <button className="drawer-close-btn" onClick={onClose}>
                                <X size={20} />
                            </button>
                        </div>

                        {/* Description */}
                        <div className="drawer-description">
                            {predictionData.description}
                        </div>

                        {/* Tabs */}
                        <div className="drawer-tabs">
                            {tabs.map(tab => {
                                const Icon = tab.icon;
                                return (
                                    <button
                                        key={tab.id}
                                        className={`drawer-tab ${activeTab === tab.id ? 'active' : ''}`}
                                        onClick={() => setActiveTab(tab.id)}
                                    >
                                        <Icon size={16} />
                                        <span>{tab.label}</span>
                                    </button>
                                );
                            })}
                        </div>

                        {/* Tab Content */}
                        <div className="drawer-content">
                            {activeTab === 'hunting' && (
                                <div className="tab-panel">
                                    <div className="tab-panel-header">
                                        <Search size={18} color="#facc15" />
                                        <h3>Threat Hunting Queries</h3>
                                    </div>
                                    <p className="tab-panel-description">
                                        Use these queries to proactively hunt for signs of this predicted tactic in your environment.
                                    </p>

                                    {predictionData.huntingQueries && predictionData.huntingQueries.length > 0 ? (
                                        <div className="query-list">
                                            {predictionData.huntingQueries.map((query, index) => (
                                                <CodeBlock
                                                    key={index}
                                                    code={query.query}
                                                    language={query.platform}
                                                    description={query.description}
                                                />
                                            ))}
                                        </div>
                                    ) : (
                                        <div className="empty-state">
                                            No hunting queries available for this tactic.
                                        </div>
                                    )}
                                </div>
                            )}

                            {activeTab === 'rules' && (
                                <div className="tab-panel">
                                    <div className="tab-panel-header">
                                        <Shield size={18} color="#facc15" />
                                        <h3>Detection Rules</h3>
                                    </div>
                                    <p className="tab-panel-description">
                                        Deploy these detection rules to your SIEM or EDR platform to block this attack vector.
                                    </p>

                                    {predictionData.detectionRules && predictionData.detectionRules.length > 0 ? (
                                        <div className="query-list">
                                            {predictionData.detectionRules.map((rule, index) => (
                                                <CodeBlock
                                                    key={index}
                                                    code={rule.rule}
                                                    language={rule.format}
                                                    description={`${rule.format} detection rule for ${predictionData.tactic}`}
                                                />
                                            ))}
                                        </div>
                                    ) : (
                                        <div className="empty-state">
                                            No detection rules available for this tactic.
                                        </div>
                                    )}
                                </div>
                            )}

                            {activeTab === 'iocs' && (
                                <div className="tab-panel">
                                    <div className="tab-panel-header">
                                        <Database size={18} color="#facc15" />
                                        <h3>Contextual IOCs</h3>
                                    </div>
                                    <p className="tab-panel-description">
                                        These indicators were captured from previous attack stages. Use them to refine your hunt.
                                    </p>

                                    {predictionData.contextIOCs && predictionData.contextIOCs.length > 0 ? (
                                        <div className="ioc-table-container">
                                            <table className="ioc-table">
                                                <thead>
                                                    <tr>
                                                        <th>Type</th>
                                                        <th>Value</th>
                                                        <th>Source Stage</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    {predictionData.contextIOCs.map((ioc, index) => (
                                                        <tr key={index}>
                                                            <td>
                                                                <span className={`ioc-type-badge ioc-type-${ioc.type.toLowerCase()}`}>
                                                                    {ioc.type}
                                                                </span>
                                                            </td>
                                                            <td className="ioc-value">{ioc.value}</td>
                                                            <td className="ioc-source">{ioc.source}</td>
                                                        </tr>
                                                    ))}
                                                </tbody>
                                            </table>
                                        </div>
                                    ) : (
                                        <div className="empty-state">
                                            <Database size={32} color="#666" />
                                            <p>No IOCs collected from previous stages.</p>
                                            <p className="empty-state-hint">
                                                IOCs are automatically extracted from parent alert nodes in the attack path.
                                            </p>
                                        </div>
                                    )}
                                </div>
                            )}
                        </div>
                    </motion.div>
                </>
            )}
        </AnimatePresence>
    );
}
