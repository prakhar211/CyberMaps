import React, { useState } from 'react';
import {
    ShieldAlert,
    Activity,
    FileSearch,
    Settings,
    ChevronRight,
    ChevronLeft
} from 'lucide-react';
import styles from '../styles/CyberHUD.module.css';

/**
 * CyberHUD Layout Wrapper
 * Provides the next-gen interface with collapsible icon dock
 */
export default function CyberHUDLayout({ children, onNavigate, currentView = 'home' }) {
    const [isDockExpanded, setIsDockExpanded] = useState(false);

    const dockItems = [
        { id: 'home', icon: ShieldAlert, label: 'Command Center', color: '#00f3ff' },
        { id: 'investigations', icon: FileSearch, label: 'Investigations', color: '#b026ff' },
        { id: 'alerts', icon: Activity, label: 'Live Alerts', color: '#ff0844' },
        { id: 'settings', icon: Settings, label: 'System Config', color: '#00f3ff' }
    ];

    return (
        <div className={styles.hudContainer}>
            {/* Collapsible Icon Dock */}
            <div
                className={`${styles.iconDock} ${isDockExpanded ? styles.expanded : ''}`}
                onMouseEnter={() => setIsDockExpanded(true)}
                onMouseLeave={() => setIsDockExpanded(false)}
            >
                {/* Logo */}
                <div className={styles.dockLogo} onClick={() => onNavigate?.('home')}>
                    <ShieldAlert size={32} />
                    <span className={styles.dockLogoText}>CyberMaps</span>
                </div>

                {/* Navigation Icons */}
                <div className={styles.dockIcons}>
                    {dockItems.map(item => {
                        const Icon = item.icon;
                        return (
                            <div
                                key={item.id}
                                className={`${styles.dockIcon} ${currentView === item.id ? styles.active : ''}`}
                                data-tooltip={item.label}
                                onClick={() => onNavigate?.(item.id)}
                            >
                                <Icon size={20} />
                            </div>
                        );
                    })}
                </div>

                {/* Expand/Collapse Indicator */}
                <div style={{
                    padding: '10px',
                    display: 'flex',
                    justifyContent: 'center',
                    opacity: 0.5
                }}>
                    {isDockExpanded ? <ChevronLeft size={16} /> : <ChevronRight size={16} />}
                </div>
            </div>

            {/* Main Canvas */}
            <div className={styles.mainCanvas}>
                {children}
            </div>
        </div>
    );
}
