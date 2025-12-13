import React, { useState } from 'react';
import { X, FileSearch } from 'lucide-react';

export default function CreateInvestigationModal({ onClose, onCreate, selectedAlertsCount }) {
    const [name, setName] = useState('');

    const handleSubmit = (e) => {
        e.preventDefault();
        if (name.trim()) {
            onCreate(name);
        }
    };

    return (
        <div style={{
            position: 'fixed',
            top: 0,
            left: 0,
            width: '100vw',
            height: '100vh',
            background: 'rgba(0,0,0,0.8)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000
        }}>
            <div className="glass-panel" style={{ width: '400px', padding: '20px', position: 'relative' }}>
                <button
                    onClick={onClose}
                    style={{ position: 'absolute', top: '10px', right: '10px', background: 'transparent', border: 'none', color: '#fff', cursor: 'pointer' }}
                >
                    <X size={20} />
                </button>

                <h2 style={{ display: 'flex', alignItems: 'center', gap: '10px', color: '#00f3ff', marginBottom: '20px' }}>
                    <FileSearch /> New Investigation
                </h2>

                <p style={{ color: '#aaa', fontSize: '0.9rem', marginBottom: '20px' }}>
                    Correlate {selectedAlertsCount} selected alerts into a unified attack path.
                </p>

                <form onSubmit={handleSubmit}>
                    <div style={{ marginBottom: '20px' }}>
                        <label style={{ display: 'block', color: '#fff', marginBottom: '5px' }}>Investigation Name</label>
                        <input
                            type="text"
                            value={name}
                            onChange={(e) => setName(e.target.value)}
                            placeholder="e.g., APT-29 Campaign, SQL Injection Incident"
                            autoFocus
                            style={{
                                width: '100%',
                                padding: '10px',
                                background: 'rgba(0,243,255,0.1)',
                                border: '1px solid #00f3ff',
                                color: '#fff',
                                borderRadius: '5px',
                                outline: 'none'
                            }}
                        />
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
                        <button
                            type="button"
                            onClick={onClose}
                            style={{
                                padding: '8px 16px',
                                background: 'transparent',
                                border: '1px solid #666',
                                color: '#aaa',
                                borderRadius: '5px',
                                cursor: 'pointer'
                            }}
                        >
                            Cancel
                        </button>
                        <button
                            type="submit"
                            disabled={!name.trim()}
                            className="btn-primary" // Reuse global class
                        >
                            Create
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}
