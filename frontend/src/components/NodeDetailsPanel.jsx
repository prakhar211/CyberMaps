import React, { useState } from 'react';
import { X, Shield, Activity, Info, User, Globe, Key, Database, Clock, AlertTriangle, Code, ChevronDown, ChevronUp } from 'lucide-react';

const NodeDetailsPanel = ({ node, tacticInfo, onClose }) => {
    const [showRawJson, setShowRawJson] = useState(false);

    if (!node) return null;

    // Get the original alert data if available
    const originalAlert = node.data?.original_alert;

    // Determine type based on label or data
    const isAlert = node.id.startsWith('alert');
    const isCrownJewel = node.data.label.includes("CROWN JEWEL");
    const isDefense = node.data.label.includes("Firewall") || node.data.label.includes("DMZ");

    // Format label
    let title = node.data.label;
    let type = "Standard Node";
    let typeColor = "#00f3ff";

    if (isAlert) {
        type = "Detected Alert";
        typeColor = "#ffcc00"; // Warning color
    } else if (isCrownJewel) {
        type = "Critical Asset";
        typeColor = "#ff0055"; // Critical color
    } else if (isDefense) {
        type = "Defense Layer";
        typeColor = "#0088ff"; // Defense color
    }

    // Extract key artifacts from the raw log if available
    const rawLog = originalAlert?.raw_log || {};
    const sourceIP = rawLog.sourceIPAddress || originalAlert?.attacker?.source_ips?.[0];
    const userIdentity = rawLog.userIdentity || {};
    const userName = userIdentity.userName || userIdentity.sessionContext?.sessionIssuer?.userName || originalAlert?.assets?.identities?.[0]?.username;
    const accountId = userIdentity.accountId || rawLog.recipientAccountId;
    const eventTime = rawLog.eventTime || originalAlert?.timestamp_utc;
    const awsRegion = rawLog.awsRegion;
    const eventSource = rawLog.eventSource;
    const userAgent = rawLog.userAgent || originalAlert?.attacker?.user_agent;
    const eventName = rawLog.eventName;

    // Extract resource details
    const requestParams = rawLog.requestParameters || {};
    const responseElements = rawLog.responseElements || {};

    // Determine if this is a cloud alert
    const isCloudAlert = eventSource || originalAlert?.name?.includes('AWS') || rawLog.eventVersion;

    // Get context-aware log sources
    const getRecommendedLogSources = () => {
        if (!isAlert) return null;

        if (isCloudAlert) {
            // Cloud-specific log sources
            const cloudLogs = [
                '• AWS CloudTrail - API activity logs',
                '• VPC Flow Logs - Network traffic analysis',
                '• AWS Config - Resource configuration changes',
                '• GuardDuty - Threat detection findings'
            ];

            // Add event-specific sources
            if (eventName?.includes('Login') || eventName?.includes('Auth')) {
                cloudLogs.push('• CloudWatch Logs - Authentication events');
            }
            if (eventName?.includes('S3') || eventName?.includes('Bucket')) {
                cloudLogs.push('• S3 Access Logs - Object-level operations');
            }
            if (eventName?.includes('Secret') || eventName?.includes('Parameter')) {
                cloudLogs.push('• Secrets Manager Audit Logs');
                cloudLogs.push('• Systems Manager Parameter Store Logs');
            }
            if (eventName?.includes('Snapshot') || eventName?.includes('Volume')) {
                cloudLogs.push('• EBS API Logs via CloudTrail');
                cloudLogs.push('• EC2 Instance Logs');
            }

            return cloudLogs;
        } else {
            // On-prem/Legacy log sources
            return [
                '• Windows Event Logs - Security & System',
                '• Syslog - Linux/Unix system logs',
                '• Firewall Logs - Network perimeter',
                '• IDS/IPS Alerts - Intrusion detection',
                '• Authentication Logs - AD/LDAP events',
                '• Application Logs - Custom app logging'
            ];
        }
    };

    // Get context-aware mitigation steps
    const getMitigationSteps = () => {
        if (!isAlert) return tacticInfo?.mitigation || null;

        if (isCloudAlert && eventName) {
            // Event-specific mitigations for cloud
            if (eventName.includes('StopLogging') || eventName.includes('DeleteTrail')) {
                return '1. Immediately re-enable CloudTrail logging\n2. Review IAM policies for unauthorized permissions\n3. Enable CloudTrail log file validation\n4. Configure SNS/EventBridge alerts for trail modifications\n5. Investigate all API calls from the source IP\n6. Rotate compromised credentials';
            }
            if (eventName.includes('CreateAccessKey')) {
                return '1. Immediately disable the newly created access key\n2. Review IAM user permissions and policies\n3. Enable MFA for all IAM users\n4. Audit all API calls made with the access key\n5. Implement least-privilege access controls\n6. Enable AWS IAM Access Analyzer';
            }
            if (eventName.includes('ConsoleLogin')) {
                return '1. Force password reset for the compromised user\n2. Enable MFA if not already enabled\n3. Review CloudTrail for unauthorized API calls\n4. Check for new IAM users/roles created\n5. Implement IP-based access restrictions\n6. Enable CloudWatch anomaly detection';
            }
            if (eventName.includes('GetSecretValue')) {
                return '1. Rotate the exposed secret immediately\n2. Review all applications using the secret\n3. Enable secret rotation policies\n4. Audit access patterns to Secrets Manager\n5. Implement least-privilege IAM policies\n6. Enable CloudWatch Logs for secret access';
            }
            if (eventName.includes('CreateSnapshot') || eventName.includes('CopySnapshot')) {
                return '1. Delete unauthorized snapshots immediately\n2. Enable EBS encryption by default\n3. Review snapshot sharing permissions\n4. Audit all data exfiltration attempts\n5. Implement DLP controls for sensitive data\n6. Enable AWS Macie for data discovery';
            }
            if (eventName.includes('DeleteBucket') || eventName.includes('Delete')) {
                return '1. Attempt data recovery from backups\n2. Enable MFA Delete for critical buckets\n3. Implement S3 Object Lock for immutability\n4. Review IAM policies for delete permissions\n5. Enable S3 versioning on all buckets\n6. Investigate for ransomware indicators';
            }
        }

        // Fallback to generic or tactic-based mitigation
        return tacticInfo?.mitigation || 'Review security logs and apply principle of least privilege. Isolate affected systems and conduct forensic analysis.';
    };

    const logSources = getRecommendedLogSources();
    const mitigationText = getMitigationSteps();

    return (
        <div className="glass-panel" style={{
            position: 'absolute',
            right: '20px',
            top: '80px',
            width: '360px',
            maxHeight: 'calc(100vh - 120px)',
            overflowY: 'auto',
            padding: '20px',
            zIndex: 20,
            borderLeft: `4px solid ${typeColor}`,
            animation: 'slideInRight 0.3s ease-out'
        }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '15px' }}>
                <div>
                    <span style={{
                        color: typeColor,
                        fontSize: '0.7rem',
                        textTransform: 'uppercase',
                        fontWeight: 'bold',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '5px'
                    }}>
                        <Activity size={12} /> {type}
                    </span>
                    <h3 style={{ margin: '5px 0', fontSize: '1.1rem', wordBreak: 'break-word' }}>{title}</h3>
                </div>
                <button
                    onClick={onClose}
                    style={{
                        background: 'transparent',
                        border: 'none',
                        color: '#aaa',
                        cursor: 'pointer',
                        padding: '0'
                    }}
                >
                    <X size={18} />
                </button>
            </div>

            <div style={{ marginBottom: '20px' }}>
                <h4 style={{ fontSize: '0.8rem', color: '#888', marginBottom: '5px', textTransform: 'uppercase' }}>Context</h4>
                <p style={{ fontSize: '0.9rem', lineHeight: '1.4' }}>
                    {originalAlert?.description || (tacticInfo ? tacticInfo.description : "No specific intelligence available for this node.")}
                </p>
            </div>

            {/* Key Artifacts Section */}
            {isAlert && rawLog && Object.keys(rawLog).length > 0 && (
                <div style={{ marginBottom: '20px' }}>
                    <h4 style={{
                        fontSize: '0.8rem',
                        color: '#ff9900',
                        marginBottom: '10px',
                        textTransform: 'uppercase',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '5px'
                    }}>
                        <AlertTriangle size={12} /> Key Artifacts
                    </h4>

                    {/* Attacker Information */}
                    {sourceIP && (
                        <div style={{
                            background: 'rgba(255, 0, 85, 0.05)',
                            padding: '10px',
                            borderRadius: '5px',
                            border: '1px solid rgba(255, 0, 85, 0.2)',
                            marginBottom: '10px'
                        }}>
                            <div style={{ fontSize: '0.75rem', color: '#ff0055', fontWeight: 'bold', marginBottom: '5px', display: 'flex', alignItems: 'center', gap: '5px' }}>
                                <Globe size={12} /> ATTACKER SOURCE
                            </div>
                            <div style={{ fontSize: '0.85rem', color: '#fff', fontFamily: 'monospace' }}>
                                {sourceIP}
                            </div>
                            {userAgent && (
                                <div style={{ fontSize: '0.7rem', color: '#aaa', marginTop: '4px' }}>
                                    User-Agent: {userAgent}
                                </div>
                            )}
                        </div>
                    )}

                    {/* Identity Information */}
                    {userName && (
                        <div style={{
                            background: 'rgba(0, 243, 255, 0.05)',
                            padding: '10px',
                            borderRadius: '5px',
                            border: '1px solid rgba(0, 243, 255, 0.2)',
                            marginBottom: '10px'
                        }}>
                            <div style={{ fontSize: '0.75rem', color: '#00f3ff', fontWeight: 'bold', marginBottom: '5px', display: 'flex', alignItems: 'center', gap: '5px' }}>
                                <User size={12} /> COMPROMISED IDENTITY
                            </div>
                            <div style={{ fontSize: '0.85rem', color: '#fff', fontFamily: 'monospace' }}>
                                {userName}
                            </div>
                            {userIdentity.type && (
                                <div style={{ fontSize: '0.7rem', color: '#aaa', marginTop: '4px' }}>
                                    Type: {userIdentity.type}
                                </div>
                            )}
                            {accountId && (
                                <div style={{ fontSize: '0.7rem', color: '#aaa', marginTop: '2px' }}>
                                    Account: {accountId}
                                </div>
                            )}
                        </div>
                    )}

                    {/* AWS Resource Details */}
                    {(requestParams.bucketName || requestParams.volumeId || requestParams.secretId || requestParams.userName || requestParams.name || responseElements.accessKey) && (
                        <div style={{
                            background: 'rgba(255, 204, 0, 0.05)',
                            padding: '10px',
                            borderRadius: '5px',
                            border: '1px solid rgba(255, 204, 0, 0.2)',
                            marginBottom: '10px'
                        }}>
                            <div style={{ fontSize: '0.75rem', color: '#ffcc00', fontWeight: 'bold', marginBottom: '5px', display: 'flex', alignItems: 'center', gap: '5px' }}>
                                <Database size={12} /> AFFECTED RESOURCES
                            </div>
                            {requestParams.bucketName && (
                                <div style={{ fontSize: '0.85rem', color: '#fff', marginTop: '4px' }}>
                                    <span style={{ color: '#888' }}>S3 Bucket:</span> {requestParams.bucketName}
                                </div>
                            )}
                            {requestParams.volumeId && (
                                <div style={{ fontSize: '0.85rem', color: '#fff', marginTop: '4px' }}>
                                    <span style={{ color: '#888' }}>EBS Volume:</span> {requestParams.volumeId}
                                </div>
                            )}
                            {responseElements.snapshotId && (
                                <div style={{ fontSize: '0.85rem', color: '#fff', marginTop: '4px' }}>
                                    <span style={{ color: '#888' }}>Snapshot:</span> {responseElements.snapshotId}
                                </div>
                            )}
                            {requestParams.secretId && (
                                <div style={{ fontSize: '0.85rem', color: '#fff', marginTop: '4px' }}>
                                    <span style={{ color: '#888' }}>Secret:</span> {requestParams.secretId}
                                </div>
                            )}
                            {requestParams.userName && (
                                <div style={{ fontSize: '0.85rem', color: '#fff', marginTop: '4px' }}>
                                    <span style={{ color: '#888' }}>IAM User:</span> {requestParams.userName}
                                </div>
                            )}
                            {requestParams.name && !requestParams.userName && (
                                <div style={{ fontSize: '0.85rem', color: '#fff', marginTop: '4px' }}>
                                    <span style={{ color: '#888' }}>Resource:</span> {requestParams.name}
                                </div>
                            )}
                            {responseElements.accessKey?.accessKeyId && (
                                <div style={{ fontSize: '0.85rem', color: '#fff', marginTop: '4px' }}>
                                    <span style={{ color: '#888' }}>Access Key:</span> {responseElements.accessKey.accessKeyId}
                                </div>
                            )}
                        </div>
                    )}

                    {/* Timestamp */}
                    {eventTime && (
                        <div style={{
                            background: 'rgba(150, 150, 150, 0.05)',
                            padding: '10px',
                            borderRadius: '5px',
                            border: '1px solid rgba(150, 150, 150, 0.2)',
                            marginBottom: '10px'
                        }}>
                            <div style={{ fontSize: '0.75rem', color: '#aaa', fontWeight: 'bold', marginBottom: '5px', display: 'flex', alignItems: 'center', gap: '5px' }}>
                                <Clock size={12} /> TIMESTAMP
                            </div>
                            <div style={{ fontSize: '0.85rem', color: '#fff', fontFamily: 'monospace' }}>
                                {new Date(eventTime).toLocaleString()}
                            </div>
                            {awsRegion && (
                                <div style={{ fontSize: '0.7rem', color: '#aaa', marginTop: '4px' }}>
                                    Region: {awsRegion}
                                </div>
                            )}
                        </div>
                    )}
                </div>
            )}

            {/* Raw JSON Viewer */}
            {isAlert && rawLog && Object.keys(rawLog).length > 0 && (
                <div style={{ marginBottom: '20px' }}>
                    <button
                        onClick={() => setShowRawJson(!showRawJson)}
                        style={{
                            background: 'rgba(100, 100, 100, 0.2)',
                            border: '1px solid rgba(150, 150, 150, 0.3)',
                            color: '#ccc',
                            padding: '8px 12px',
                            borderRadius: '5px',
                            cursor: 'pointer',
                            fontSize: '0.8rem',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '8px',
                            width: '100%',
                            justifyContent: 'space-between'
                        }}
                    >
                        <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <Code size={14} />
                            View Raw Event JSON
                        </span>
                        {showRawJson ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                    </button>

                    {showRawJson && (
                        <div style={{
                            marginTop: '10px',
                            background: '#0a0a0a',
                            border: '1px solid #333',
                            borderRadius: '5px',
                            padding: '12px',
                            maxHeight: '300px',
                            overflowY: 'auto',
                            fontSize: '0.75rem',
                            fontFamily: 'monospace',
                            color: '#0f0'
                        }}>
                            <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                                {JSON.stringify(rawLog, null, 2)}
                            </pre>
                        </div>
                    )}
                </div>
            )}

            {/* Recommended Log Sources */}
            {logSources && (
                <div style={{ marginBottom: '20px' }}>
                    <h4 style={{ fontSize: '0.8rem', color: '#888', marginBottom: '8px', textTransform: 'uppercase' }}>
                        {isCloudAlert ? '☁️ Cloud Log Sources' : '🖥️ On-Prem Log Sources'}
                    </h4>
                    <div style={{ fontSize: '0.85rem', color: '#eee', lineHeight: '1.6' }}>
                        {logSources.map((log, i) => (
                            <div key={i} style={{ marginBottom: '4px' }}>
                                {log}
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Mitigation Steps */}
            {mitigationText && (
                <div style={{ background: 'rgba(0, 255, 100, 0.05)', padding: '12px', borderRadius: '5px', border: '1px solid rgba(0, 255, 100, 0.2)' }}>
                    <h4 style={{ fontSize: '0.8rem', color: '#00ff88', marginBottom: '8px', textTransform: 'uppercase', display: 'flex', alignItems: 'center', gap: '5px' }}>
                        <Shield size={12} /> {isCloudAlert ? 'Cloud Mitigation Steps' : 'Mitigation Steps'}
                    </h4>
                    <div style={{ fontSize: '0.85rem', lineHeight: '1.5', color: '#eee', whiteSpace: 'pre-line' }}>
                        {mitigationText}
                    </div>
                </div>
            )}

            <style>{`
        @keyframes slideInRight {
          from { opacity: 0; transform: translateX(20px); }
          to { opacity: 1; transform: translateX(0); }
        }
      `}</style>
        </div>
    );
};

export default NodeDetailsPanel;
