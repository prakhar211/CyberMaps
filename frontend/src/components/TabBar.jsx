import React from 'react';
import '../styles/TabBar.css';
import { Network, X } from 'lucide-react';

export default function TabBar({ tabs, activeTabId, onTabClick, onCloseTab }) {
    return (
        <div className="tab-bar-container">
            {tabs.map(tab => (
                <div
                    key={tab.id}
                    className={`tab ${tab.id === activeTabId ? 'active' : ''} ${tab.type}`}
                    onClick={() => onTabClick(tab.id)}
                    title={tab.title}
                >
                    <div className="tab-icon">
                        {tab.type === 'strategic' ? <Network size={14} /> : <div style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--neon-crimson)' }} />}
                    </div>
                    <span className="tab-title">{tab.title}</span>
                    {tab.closable && (
                        <div
                            className="tab-close"
                            onClick={(e) => {
                                e.stopPropagation();
                                onCloseTab(tab.id);
                            }}
                        >
                            <X size={10} />
                        </div>
                    )}
                </div>
            ))}
        </div>
    );
}
