import React from 'react';
import styles from '../styles/CyberHUD.module.css';

/**
 * Theme Toggle Switch (V1/V2)
 * Allows switching between classic and Cyber HUD themes
 */
export default function ThemeToggle({ isV2, onToggle }) {
    return (
        <div className={styles.themeToggle} onClick={onToggle}>
            <span style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '1px' }}>
                {isV2 ? 'Cyber HUD' : 'Classic'}
            </span>
            <div className={`${styles.toggleSwitch} ${isV2 ? styles.active : ''}`}>
                <div className={styles.toggleKnob} />
            </div>
        </div>
    );
}
