import React, { useState } from 'react';
import { X, ShieldPlus } from 'lucide-react';
import axios from 'axios';

const TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact"
];

function AddAlertModal({ onClose, onAlertAdded }) {
    const [formData, setFormData] = useState({
        name: '',
        severity: 'Medium',
        tactic: 'Initial Access',
        description: ''
    });
    const [loading, setLoading] = useState(false);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        try {
            // Parse Raw Data if present
            let rawDataJson = null;
            if (formData.raw_data_str && formData.raw_data_str.trim() !== "") {
                if (formData.raw_data_str.length > 10000) {
                    alert("JSON Logs too large! Limit is 10,000 characters.");
                    setLoading(false);
                    return;
                }

                try {
                    rawDataJson = JSON.parse(formData.raw_data_str);
                } catch (e) {
                    alert("Invalid JSON in Raw Logs field. Please correct it.");
                    setLoading(false);
                    return;
                }
            }

            // Generate a random ID for now
            const newAlert = {
                ...formData,
                id: `manual-${Date.now()}`,
                technique: "Manual Entry",
                raw_data: rawDataJson
            };
            const res = await axios.post('http://localhost:8000/alerts', newAlert);
            onAlertAdded(res.data);
            onClose();
        } catch (err) {
            console.error("Failed to add alert:", err);
            alert("Failed to add alert");
        } finally {
            setLoading(false);
        }
    };

    return (
        <div style={{
            position: 'fixed', top: 0, left: 0, width: '100%', height: '100%',
            background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(5px)',
            display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1000
        }}>
            <div className="glass-panel" style={{ width: '400px', padding: '20px', position: 'relative' }}>
                <button onClick={onClose} style={{ position: 'absolute', top: 10, right: 10, background: 'none', border: 'none', color: '#fff', cursor: 'pointer' }}>
                    <X size={20} />
                </button>

                <div style={{ display: 'flex', alignItems: 'center', marginBottom: '20px' }}>
                    <ShieldPlus size={24} color="var(--accent-primary)" />
                    <h3 style={{ margin: '0 0 0 10px' }}>Add Alerts</h3>
                </div>

                <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
                    <div>
                        <label style={{ display: 'block', fontSize: '0.8rem', color: '#ccc', marginBottom: '5px' }}>Alert Name</label>
                        <input
                            type="text"
                            required
                            value={formData.name}
                            onChange={e => setFormData({ ...formData, name: e.target.value })}
                            style={{ width: '100%', background: 'rgba(255,255,255,0.1)', border: '1px solid var(--border-color)', color: '#fff', padding: '8px', borderRadius: '4px' }}
                        />
                    </div>

                    <div>
                        <label style={{ display: 'block', fontSize: '0.8rem', color: '#ccc', marginBottom: '5px' }}>Tactic</label>
                        <select
                            value={formData.tactic}
                            onChange={e => setFormData({ ...formData, tactic: e.target.value })}
                            style={{ width: '100%', background: 'rgba(255,255,255,0.1)', border: '1px solid var(--border-color)', color: '#fff', padding: '8px', borderRadius: '4px' }}
                        >
                            {TACTICS.map(t => <option key={t} value={t} style={{ background: '#222' }}>{t}</option>)}
                        </select>
                    </div>

                    <div>
                        <label style={{ display: 'block', fontSize: '0.8rem', color: '#ccc', marginBottom: '5px' }}>Severity</label>
                        <select
                            value={formData.severity}
                            onChange={e => setFormData({ ...formData, severity: e.target.value })}
                            style={{ width: '100%', background: 'rgba(255,255,255,0.1)', border: '1px solid var(--border-color)', color: '#fff', padding: '8px', borderRadius: '4px' }}
                        >
                            <option value="Low" style={{ background: '#222' }}>Low</option>
                            <option value="Medium" style={{ background: '#222' }}>Medium</option>
                            <option value="High" style={{ background: '#222' }}>High</option>
                            <option value="Critical" style={{ background: '#222' }}>Critical</option>
                        </select>
                    </div>

                    <div>
                        <label style={{ display: 'block', fontSize: '0.8rem', color: '#ccc', marginBottom: '5px' }}>Description</label>
                        <textarea
                            value={formData.description}
                            onChange={e => setFormData({ ...formData, description: e.target.value })}
                            style={{ width: '100%', background: 'rgba(255,255,255,0.1)', border: '1px solid var(--border-color)', color: '#fff', padding: '8px', borderRadius: '4px', minHeight: '60px' }}
                        />
                    </div>

                    <div>
                        <label style={{ display: 'block', fontSize: '0.8rem', color: '#ccc', marginBottom: '5px' }}>
                            Raw JSON Logs
                            <span style={{ fontSize: '0.7rem', color: '#888', marginLeft: '5px' }}>(Optional)</span>
                        </label>
                        <textarea
                            value={formData.raw_data_str || ''}
                            onChange={e => setFormData({ ...formData, raw_data_str: e.target.value })}
                            placeholder='{"Source IP": "192.168.1.10", ...}'
                            style={{
                                width: '100%',
                                background: 'rgba(255,255,255,0.1)',
                                border: '1px solid var(--border-color)',
                                color: '#ccc',
                                fontFamily: 'monospace',
                                fontSize: '0.8rem',
                                padding: '8px',
                                borderRadius: '4px',
                                minHeight: '80px'
                            }}
                        />
                    </div>

                    <button type="submit" className="btn-primary" disabled={loading} style={{ marginTop: '10px' }}>
                        {loading ? 'Adding...' : 'Add Alerts'}
                    </button>
                </form>
            </div>
        </div>
    );
}

export default AddAlertModal;
