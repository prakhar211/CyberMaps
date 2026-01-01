/**
 * IOC (Indicator of Compromise) Collector Utility
 * Traverses the attack graph backwards to collect IOCs from previous alert stages
 */

/**
 * Collects IOCs from parent nodes in the attack graph
 * @param {Object} selectedNode - The currently selected predicted node
 * @param {Array} nodes - All nodes in the graph
 * @param {Array} edges - All edges in the graph
 * @returns {Array} Array of IOC objects with type, value, and source
 */
export function collectPastIOCs(selectedNode, nodes, edges) {
    if (!selectedNode || !nodes || !edges) {
        return [];
    }

    const iocs = [];
    const visitedNodes = new Set();
    const nodesToProcess = [selectedNode.id];

    // Breadth-first traversal to find all ancestor nodes
    while (nodesToProcess.length > 0) {
        const currentNodeId = nodesToProcess.shift();

        if (visitedNodes.has(currentNodeId)) {
            continue;
        }
        visitedNodes.add(currentNodeId);

        // Find all edges that point TO this node (parent edges)
        const parentEdges = edges.filter(edge => edge.target === currentNodeId);

        for (const edge of parentEdges) {
            const parentNode = nodes.find(n => n.id === edge.source);

            if (!parentNode) continue;

            // Only collect IOCs from actual alert nodes (not predicted nodes)
            // Predicted nodes have IDs starting with 'pred-'
            if (!parentNode.id.startsWith('pred-')) {
                // Extract IOCs from the alert node
                const nodeIOCs = extractIOCsFromNode(parentNode);
                iocs.push(...nodeIOCs);

                // Continue traversing to find more ancestors
                nodesToProcess.push(parentNode.id);
            }
        }
    }

    // Remove duplicates based on type + value combination
    const uniqueIOCs = [];
    const seen = new Set();

    for (const ioc of iocs) {
        const key = `${ioc.type}:${ioc.value}`;
        if (!seen.has(key)) {
            seen.add(key);
            uniqueIOCs.push(ioc);
        }
    }

    return uniqueIOCs;
}

/**
 * Extracts IOC data from a node's metadata
 * @param {Object} node - The node to extract IOCs from
 * @returns {Array} Array of IOC objects
 */
function extractIOCsFromNode(node) {
    const iocs = [];

    // Check if node has IOC data in its data object
    if (node.data && node.data.iocs) {
        return node.data.iocs;
    }

    // For now, generate mock IOCs based on node label
    // In a real implementation, this would come from the alert data
    const nodeName = node.data?.label || 'Unknown';
    const nodeSource = nodeName.split(':')[0] || 'Alert Node';

    // Mock IOC generation based on common alert patterns
    if (nodeName.toLowerCase().includes('initial access')) {
        iocs.push({
            type: 'IP',
            value: '192.168.1.45',
            source: nodeSource
        });
    }

    if (nodeName.toLowerCase().includes('persistence')) {
        iocs.push({
            type: 'User',
            value: 'admin_backup',
            source: nodeSource
        });
    }

    if (nodeName.toLowerCase().includes('credential')) {
        iocs.push({
            type: 'Process',
            value: 'lsass.exe',
            source: nodeSource
        });
    }

    if (nodeName.toLowerCase().includes('lateral')) {
        iocs.push({
            type: 'Hash',
            value: 'a3f7b2c1d4e5f6g7h8i9j0k1l2m3n4o5',
            source: nodeSource
        });
    }

    if (nodeName.toLowerCase().includes('execution')) {
        iocs.push({
            type: 'File',
            value: 'C:\\Windows\\Temp\\malware.exe',
            source: nodeSource
        });
    }

    return iocs;
}

/**
 * Mock prediction data generator
 * @param {Object} node - The predicted node
 * @param {Array} contextIOCs - IOCs collected from parent nodes
 * @returns {Object} Prediction data structure
 */
export function generatePredictionData(node, contextIOCs) {
    if (!node || !node.data) {
        return null;
    }

    const label = node.data.label || '';
    const probabilityMatch = label.match(/\((\d+)%\)/);
    const probability = probabilityMatch ? `${probabilityMatch[1]}%` : '50%';

    // Extract tactic name (remove probability part)
    const tactic = label.replace(/\s*\(\d+%\)/, '').trim();

    return {
        tactic,
        probability,
        description: `Adversary may attempt to execute ${tactic.toLowerCase()} techniques based on observed attack patterns.`,
        huntingQueries: getHuntingQueries(tactic),
        detectionRules: getDetectionRules(tactic),
        contextIOCs
    };
}

/**
 * Get hunting queries for a specific tactic
 */
function getHuntingQueries(tactic) {
    const tacticLower = tactic.toLowerCase();

    const queries = {
        'credential access': [
            {
                platform: 'KQL (Sentinel)',
                query: `SecurityEvent\n| where EventID == 4624 and LogonType == 10\n| where AccountName contains "admin"\n| project TimeGenerated, Computer, AccountName, IpAddress`,
                description: 'Detect suspicious RDP logins associated with flagged accounts.'
            },
            {
                platform: 'Splunk',
                query: `index=windows EventCode=4624 LogonType=10\n| search AccountName="admin*"\n| table _time, host, AccountName, src_ip`,
                description: 'Hunt for remote desktop logins from privileged accounts.'
            }
        ],
        'lateral movement': [
            {
                platform: 'KQL (Sentinel)',
                query: `SecurityEvent\n| where EventID in (4624, 4672)\n| where LogonType == 3\n| summarize count() by AccountName, IpAddress, Computer\n| where count_ > 5`,
                description: 'Identify accounts authenticating to multiple systems.'
            },
            {
                platform: 'Splunk',
                query: `index=windows (EventCode=4624 OR EventCode=4672) LogonType=3\n| stats count by AccountName, src_ip, dest\n| where count > 5`,
                description: 'Detect lateral movement patterns across network.'
            }
        ],
        'persistence': [
            {
                platform: 'KQL (Sentinel)',
                query: `SecurityEvent\n| where EventID == 4698\n| project TimeGenerated, Computer, TaskName, AccountName\n| order by TimeGenerated desc`,
                description: 'Hunt for scheduled task creation events.'
            }
        ],
        'collection': [
            {
                platform: 'KQL (Sentinel)',
                query: `DeviceFileEvents\n| where ActionType == "FileCreated"\n| where FileName endswith ".zip" or FileName endswith ".rar"\n| where FolderPath contains "temp"\n| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName`,
                description: 'Detect potential data staging in temp directories.'
            }
        ],
        'exfiltration': [
            {
                platform: 'KQL (Sentinel)',
                query: `NetworkConnectionEvents\n| where RemotePort in (443, 8080, 21)\n| summarize TotalBytes = sum(SentBytes) by RemoteIP, DeviceName\n| where TotalBytes > 100000000\n| order by TotalBytes desc`,
                description: 'Identify large outbound data transfers.'
            }
        ]
    };

    // Return specific queries or default
    for (const [key, value] of Object.entries(queries)) {
        if (tacticLower.includes(key)) {
            return value;
        }
    }

    // Default query
    return [
        {
            platform: 'KQL (Sentinel)',
            query: `SecurityEvent\n| where TimeGenerated > ago(24h)\n| where EventID in (4624, 4625, 4672)\n| summarize count() by AccountName, Computer\n| order by count_ desc`,
            description: 'General authentication event analysis.'
        }
    ];
}

/**
 * Get detection rules for a specific tactic
 */
function getDetectionRules(tactic) {
    const tacticLower = tactic.toLowerCase();

    const rules = {
        'credential access': [
            {
                format: 'SIGMA',
                rule: `title: LSASS Memory Dump Detection
description: Detects credential dumping from LSASS memory
status: experimental
logsource:
  category: process_access
  product: windows
detection:
  selection:
    TargetImage|endswith: '\\lsass.exe'
    GrantedAccess: '0x1010'
  condition: selection
falsepositives:
  - Legitimate administration tools
level: high`
            }
        ],
        'lateral movement': [
            {
                format: 'SIGMA',
                rule: `title: Suspicious SMB Authentication
description: Detects lateral movement via SMB
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: 3
    AuthenticationPackageName: 'NTLM'
  condition: selection
level: medium`
            }
        ],
        'persistence': [
            {
                format: 'SIGMA',
                rule: `title: Scheduled Task Creation
description: Detects creation of scheduled tasks
status: stable
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4698
  condition: selection
falsepositives:
  - Software installations
level: medium`
            }
        ],
        'collection': [
            {
                format: 'YARA',
                rule: `rule data_staging_archive {
    meta:
        description = "Detects archive creation in temp directories"
        author = "Security Team"
    strings:
        $zip = { 50 4B 03 04 }
        $rar = { 52 61 72 21 }
    condition:
        any of them
}`
            }
        ],
        'exfiltration': [
            {
                format: 'SIGMA',
                rule: `title: Large Outbound Data Transfer
description: Detects unusual large outbound transfers
status: experimental
logsource:
  category: firewall
detection:
  selection:
    direction: outbound
  filter:
    bytes_sent: '>100000000'
  condition: selection and filter
level: high`
            }
        ]
    };

    // Return specific rules or default
    for (const [key, value] of Object.entries(rules)) {
        if (tacticLower.includes(key)) {
            return value;
        }
    }

    // Default rule
    return [
        {
            format: 'SIGMA',
            rule: `title: Generic Suspicious Activity
description: Monitors for suspicious behavior patterns
status: experimental
logsource:
  product: windows
detection:
  selection:
    EventID: 
      - 4688
      - 4624
  condition: selection
level: informational`
        }
    ];
}
