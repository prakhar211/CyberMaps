import React from 'react';
import { PlusCircle, FileSearch, Zap } from 'lucide-react';
import styles from '../styles/CyberHUD.module.css';

/**
 * Floating Action Bar
 * Bottom-center command palette for primary actions
 */
export default function FloatingActionBar({
    onAddAlert,
    onNewInvestigation,
    onPredict,
    isPredicting = false
}) {
    return (
        <div className={styles.floatingActions}>
            <button
                className={styles.actionBtn}
                onClick={onAddAlert}
            >
                <PlusCircle size={16} />
                Add Alert
            </button>

            <button
                className={styles.actionBtn}
                onClick={onNewInvestigation}
            >
                <FileSearch size={16} />
                New Investigation
            </button>

            <button
                className={`${styles.actionBtn} ${styles.primary}`}
                onClick={onPredict}
                disabled={isPredicting}
            >
                <Zap size={16} />
                {isPredicting ? 'Analyzing...' : 'Predict Next Step'}
            </button>
        </div>
    );
}
