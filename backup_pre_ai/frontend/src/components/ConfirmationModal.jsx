import React from 'react';
import { AlertTriangle, X } from 'lucide-react';

export default function ConfirmationModal({
    message,
    onConfirm,
    onCancel,
    title = "Confirm Action",
    confirmText = "Confirm",
    confirmColor = "#ff0055"
}) {
    return (
        <div className="modal-overlay">
            <div className="glass-panel modal-content" style={{ maxWidth: '400px', textAlign: 'center' }}>
                <button
                    className="modal-close"
                    onClick={onCancel}
                    style={{ position: 'absolute', top: '10px', right: '10px', background: 'none', border: 'none', color: '#666', cursor: 'pointer' }}
                >
                    <X size={20} />
                </button>

                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', marginBottom: '20px' }}>
                    <AlertTriangle size={48} color={confirmColor} style={{ marginBottom: '15px' }} />
                    <h2 style={{ fontSize: '1.2rem', margin: '0 0 10px 0', textTransform: 'uppercase', letterSpacing: '1px' }}>{title}</h2>
                    <p style={{ color: '#ccc', fontSize: '0.9rem', lineHeight: '1.4' }}>{message}</p>
                </div>

                <div style={{ display: 'flex', gap: '10px', justifyContent: 'center' }}>
                    <button
                        className="btn-secondary"
                        onClick={onCancel}
                        style={{ flex: 1 }}
                    >
                        Cancel
                    </button>
                    <button
                        className="btn-primary"
                        onClick={onConfirm}
                        style={{
                            flex: 1,
                            borderColor: confirmColor,
                            background: `linear-gradient(45deg, ${confirmColor}, #550022)`
                        }}
                    >
                        {confirmText}
                    </button>
                </div>
            </div>
        </div>
    );
}
