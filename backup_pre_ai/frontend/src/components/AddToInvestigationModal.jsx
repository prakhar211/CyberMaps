import React, { useState } from 'react';
import { FileSearch, PlusCircle, X } from 'lucide-react';

export default function AddToInvestigationModal({
    onClose,
    onAdd,
    investigations = [],
    currentInvestigationId,
    selectedCount
}) {
    const [selectedInvId, setSelectedInvId] = useState(currentInvestigationId || (investigations.length > 0 ? investigations[0].id : null));

    const handleSubmit = () => {
        if (selectedInvId) {
            onAdd(selectedInvId);
        }
    };

    return (
        <div className="modal-overlay">
            <div className="glass-panel modal-content" style={{ width: '400px' }}>
                <button className="modal-close" onClick={onClose}><X size={20} /></button>

                <h2 style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px' }}>
                    <PlusCircle color="#ffcc00" /> Add to Investigation
                </h2>

                <p style={{ color: '#ccc', marginBottom: '20px', fontSize: '0.9rem' }}>
                    Add <strong>{selectedCount}</strong> alert(s) to an existing investigation. The attack path will be re-analyzed.
                </p>

                <div style={{ marginBottom: '20px' }}>
                    <label style={{ display: 'block', marginBottom: '10px', color: '#00f3ff', fontSize: '0.8rem' }}>SELECT TARGET INVESTIGATION</label>
                    <div style={{ maxHeight: '200px', overflowY: 'auto', border: '1px solid rgba(255, 255, 255, 0.1)', borderRadius: '4px' }}>
                        {investigations.length === 0 ? (
                            <div style={{ padding: '10px', color: '#666', fontStyle: 'italic' }}>No investigations found.</div>
                        ) : (
                            investigations.map(inv => (
                                <div
                                    key={inv.id}
                                    onClick={() => setSelectedInvId(inv.id)}
                                    style={{
                                        padding: '10px',
                                        cursor: 'pointer',
                                        background: selectedInvId === inv.id ? 'rgba(0, 243, 255, 0.2)' : 'transparent',
                                        borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
                                        display: 'flex',
                                        alignItems: 'center',
                                        gap: '10px'
                                    }}
                                >
                                    <FileSearch size={14} color={selectedInvId === inv.id ? '#00f3ff' : '#666'} />
                                    <div style={{ flex: 1 }}>
                                        <div style={{ fontSize: '0.9rem', color: selectedInvId === inv.id ? '#fff' : '#aaa' }}>{inv.name}</div>
                                        <div style={{ fontSize: '0.7rem', color: '#666' }}>{new Date(inv.created_at).toLocaleTimeString()}</div>
                                    </div>
                                    {selectedInvId === inv.id && (
                                        <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#00f3ff', boxShadow: '0 0 5px #00f3ff' }}></div>
                                    )}
                                </div>
                            ))
                        )}
                    </div>
                </div>

                <button
                    className="btn-primary"
                    onClick={handleSubmit}
                    disabled={!selectedInvId}
                    style={{ width: '100%', background: 'linear-gradient(90deg, #ffcc00, #ff8800)', border: 'none', color: '#000', fontWeight: 'bold' }}
                >
                    Add Alerts & Update Path
                </button>
            </div>
        </div>
    );
}
