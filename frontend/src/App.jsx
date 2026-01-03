import React, { useState, useCallback, useRef, useEffect } from 'react';
import ReactFlow, {
  ReactFlowProvider,
  addEdge,
  useNodesState,
  useEdgesState,
  Controls,
  Background,
  MarkerType
} from 'reactflow';
import AttackGraph from './components/AttackGraph';
import AddAlertModal from './components/AddAlertModal';
import CreateInvestigationModal from './components/CreateInvestigationModal';
import AddToInvestigationModal from './components/AddToInvestigationModal';
import ConfirmationModal from './components/ConfirmationModal';
import NodeDetailsPanel from './components/NodeDetailsPanel';
import InvestigationSummary from './components/InvestigationSummary';
import PredictionDrawer from './components/PredictionDrawer';
import DeviceNode from './components/DeviceNode';
import DeviceNodeEnhanced from './components/DeviceNodeEnhanced';
import CyberHUDLayout from './components/CyberHUDLayout';
import FloatingActionBar from './components/FloatingActionBar';
import { ShieldAlert, PlusCircle, Trash2, FileSearch, CheckSquare, Square, Home, ChevronLeft, ChevronRight, Maximize2, Minimize2 } from 'lucide-react';
import ThemeToggle from './components/ThemeToggle';
import axios from 'axios';
import './index.css';
import 'reactflow/dist/style.css';
import './styles/KillChainHUD.css';
import { collectPastIOCs, generatePredictionData } from './utils/iocCollector';
import dagre from 'dagre';

const dagreGraph = new dagre.graphlib.Graph();
dagreGraph.setDefaultEdgeLabel(() => ({}));

const nodeWidth = 180;
const nodeHeight = 80;

const getLayoutedElements = (nodes, edges, direction = 'TB') => {
  const isHorizontal = direction === 'LR';
  dagreGraph.setGraph({ rankdir: direction });

  nodes.forEach((node) => {
    dagreGraph.setNode(node.id, { width: nodeWidth, height: nodeHeight });
  });

  edges.forEach((edge) => {
    dagreGraph.setEdge(edge.source, edge.target);
  });

  dagre.layout(dagreGraph);

  const layoutedNodes = nodes.map((node) => {
    const nodeWithPosition = dagreGraph.node(node.id);
    node.targetPosition = isHorizontal ? 'left' : 'top';
    node.sourcePosition = isHorizontal ? 'right' : 'bottom';

    // We are shifting the dagre node position (anchor=center center) to the top left
    // so it matches the React Flow node anchor point (top left).
    node.position = {
      x: nodeWithPosition.x - nodeWidth / 2,
      y: nodeWithPosition.y - nodeHeight / 2,
    };

    return node;
  });

  return { nodes: layoutedNodes, edges };
};

const API_BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

// --- Session Handling for Isolation ---
// Generate a unique Session ID if it doesn't exist to isolate Playground users
const getSessionId = () => {
  let sessionId = sessionStorage.getItem('cybermaps_session_id');
  if (!sessionId) {
    // Simple random ID generation (UUID-like)
    sessionId = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
      var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
    sessionStorage.setItem('cybermaps_session_id', sessionId);
  }
  return sessionId;
};
const SESSION_ID = getSessionId();
// Set global Axios header
axios.defaults.headers.common['X-Session-ID'] = SESSION_ID;

// Add an interceptor to automatically add session_id query param to every request
// This is a fail-safe in case custom headers are stripped by proxies (Render/Cloudflare)
axios.interceptors.request.use((config) => {
  config.params = config.params || {};
  config.params['session_id'] = SESSION_ID;
  return config;
});

console.log("Initialized Session:", SESSION_ID);
// --------------------------------------

// Custom Node Types
const nodeTypes = {
  activeDirectory: DeviceNode, // Map to existing generic node for now, or create specific
  firewall: DeviceNode,
  server: DeviceNode,
  endpoint: DeviceNode,
  internet: DeviceNode,
  // Add map for simplified types
  default: DeviceNode,
  // Enhanced Node
  enhanced: DeviceNodeEnhanced,
  // Restore legacy types for backward compatibility
  deviceNode: DeviceNode,
  deviceNodeEnhanced: DeviceNodeEnhanced
};

const initialNodes = [
  { id: '1', type: 'internet', position: { x: 0, y: 0 }, data: { label: 'Internet', icon: 'Internet' } },
  { id: '2', type: 'firewall', position: { x: 0, y: 100 }, data: { label: 'Corporate Firewall', icon: 'Firewall' } },
  { id: '3', type: 'server', position: { x: -100, y: 200 }, data: { label: 'DMZ Web Server', icon: 'Server' } },
  { id: '4', type: 'server', position: { x: 100, y: 200 }, data: { label: 'Internal DB', icon: 'Database', branch: 'crown-jewel' } },
  { id: '5', type: 'endpoint', position: { x: 0, y: 300 }, data: { label: 'Admin Workstation', icon: 'Workstation' } },
];

const initialEdges = [
  { id: 'e1-2', source: '1', target: '2', animated: true, style: { stroke: '#00f3ff' } },
  { id: 'e2-3', source: '2', target: '3', animated: true, style: { stroke: '#00f3ff' } },
  { id: 'e2-4', source: '2', target: '4', animated: true, style: { stroke: '#ff0055' } }, // Path to crown jewel
  { id: 'e4-5', source: '4', target: '5', animated: true, style: { stroke: '#00f3ff' } },
];


function CyberMapsApp() {
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);
  const [reactFlowInstance, setReactFlowInstance] = useState(null);
  const reactFlowWrapper = useRef(null);

  // Alert State
  const [alerts, setAlerts] = useState([]);
  const [showModal, setShowModal] = useState(false);

  // Investigation Modal State
  const [showInvestigationModal, setShowInvestigationModal] = useState(false);
  const [showAddToInvestigationModal, setShowAddToInvestigationModal] = useState(false);
  const [investigations, setInvestigations] = useState([]);

  // Delete Confirmation State
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [investigationToDelete, setInvestigationToDelete] = useState(null);

  const [predicting, setPredicting] = useState(false);

  const [selectedNode, setSelectedNode] = useState(null);
  const [tacticInfo, setTacticInfo] = useState(null);

  const [selectedAlerts, setSelectedAlerts] = useState(new Set());

  const [currentInvestigation, setCurrentInvestigation] = useState(null);
  const [investigationSummary, setInvestigationSummary] = useState(null);
  const [showInvestigationSummary, setShowInvestigationSummary] = useState(false);

  // Panel collapse state
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false);
  const [isSummaryCollapsed, setIsSummaryCollapsed] = useState(false);
  const [isSummaryExpanded, setIsSummaryExpanded] = useState(false);



  // V2 Visualization Toggle (Kill Chain HUD)
  const [useV2Viz, setUseV2Viz] = useState(false);

  // Prediction Drawer State
  const [showPredictionDrawer, setShowPredictionDrawer] = useState(false);
  const [predictionData, setPredictionData] = useState(null);

  // Current Investigation State (for Summary/Context)
  // const [activeTabId, setActiveTabId] = useState('strategic'); // REMOVED

  useEffect(() => {
    fetchAlerts();
    fetchInvestigations(); // Load investigations on mount
  }, []);

  // Selection Listener
  useEffect(() => {
    const selected = nodes.filter(n => n.selected);
    if (selected.length === 1) {
      const node = selected[0];
      setSelectedNode(node);

      // Check if this is a predicted node (has percentage in label)
      const isPredicted = node.id.startsWith('pred-') || /\(\d+%\)/.test(node.data.label);

      if (!isPredicted) {
        // Close prediction drawer for non-predicted nodes
        setShowPredictionDrawer(false);

        const label = node.data.label;
        let tactic = label.split(':')[0].trim();

        if (tactic) {
          axios.get(`${API_BASE_URL}/tactic/${tactic}`)
            .then(res => setTacticInfo(res.data))
            .catch(() => setTacticInfo(null));
        }
      }
      // NOTE: For predicted nodes, drawer opening is handled by handleNodeDoubleClick only

    } else {
      setSelectedNode(null);
      setTacticInfo(null);
      setShowPredictionDrawer(false);
    }
  }, [nodes, edges]);




  const fetchAlerts = () => {
    axios.get(`${API_BASE_URL}/alerts`)
      .then(res => setAlerts(res.data))
      .catch(err => console.error("Failed to fetch alerts:", err));
  };

  const fetchInvestigations = () => {
    axios.get(`${API_BASE_URL}/investigations`)
      .then(res => {
        setInvestigations(res.data);
      })
      .catch(err => console.error("Failed to fetch investigations:", err));
  };

  // Handle node double-click - specifically for predicted nodes
  // Using double-click instead of single-click to prevent interference with dragging
  const handleNodeDoubleClick = useCallback((event, node) => {
    // Check if this is a predicted node
    const isPredicted = node.id.startsWith('pred-') || /\(\d+%\)/.test(node.data.label);

    if (isPredicted) {
      // Open prediction drawer for predicted nodes
      const iocs = collectPastIOCs(node, nodes, edges);
      const data = generatePredictionData(node, iocs);
      setPredictionData(data);
      setShowPredictionDrawer(true);
      setSelectedNode(node);
    }
  }, [nodes, edges]);

  const loadInvestigation = (inv) => {
    if (!inv.graph || !inv.graph.nodes) return;

    const { nodes: newNodes, edges: newEdges } = inv.graph;

    // Apply Dagre Auto-Layout
    const { nodes: layoutedNodes, edges: layoutedEdges } = getLayoutedElements(
      newNodes,
      newEdges
    );

    // Directly set state
    setNodes(layoutedNodes);
    setEdges(layoutedEdges);
    setCurrentInvestigation(inv);

    // Initial Loading State for Summary
    setInvestigationSummary(null);
    setShowInvestigationSummary(false);

    axios.get(`${API_BASE_URL}/investigations/${inv.id}/summary`)
      .then(res => {
        setInvestigationSummary(res.data);
      })
      .catch(err => {
        console.error("Failed to fetch summary:", err);
        setInvestigationSummary({ error: true, message: "Failed to load summary." });
      });

    // Fit view after small delay to allow render
    setTimeout(() => {
      if (reactFlowInstance) reactFlowInstance.fitView();
    }, 100);
  };



  const handleGoHome = () => {
    setNodes(initialNodes);
    setEdges(initialEdges);
    setCurrentInvestigation(null);
    setInvestigationSummary(null);
    setShowInvestigationSummary(false);
    setTimeout(() => {
      if (reactFlowInstance) reactFlowInstance.fitView();
    }, 50);
  };

  // Toggle V2 visualization - switch node types
  useEffect(() => {
    setNodes(currentNodes => currentNodes.map(node => ({
      ...node,
      type: useV2Viz ? 'deviceNodeEnhanced' : 'deviceNode'
    })));
  }, [useV2Viz, setNodes]);

  const toggleAlertSelection = (id) => {
    const newSelection = new Set(selectedAlerts);
    if (newSelection.has(id)) newSelection.delete(id);
    else newSelection.add(id);
    setSelectedAlerts(newSelection);
  };

  const handleOpenInvestigationModal = () => {
    if (selectedAlerts.size === 0) {
      alert("Please select at least one alert to investigate.");
      return;
    }
    setShowInvestigationModal(true);
  };

  const submitInvestigation = async (name) => {
    setShowInvestigationModal(false);
    setPredicting(true);

    try {
      const res = await axios.post(`${API_BASE_URL}/correlate`, {
        name: name,
        alert_ids: Array.from(selectedAlerts)
      });

      if (!res.data || !res.data.graph) {
        throw new Error("Invalid response from server");
      }

      loadInvestigation(res.data);
      fetchInvestigations();
      setSelectedAlerts(new Set());

    } catch (err) {
      console.error("Investigation failed", err);
      alert("Failed to create investigation.");
    } finally {
      setPredicting(false);
    }
  };

  const handleOpenAddToInvestigation = () => {
    if (selectedAlerts.size === 0) {
      alert("Select alerts to add.");
      return;
    }
    setShowAddToInvestigationModal(true);
  };

  const addToInvestigation = async (targetInvId) => {
    setShowAddToInvestigationModal(false);

    if (!targetInvId) return;

    try {
      const res = await axios.put(`${API_BASE_URL}/investigations/${targetInvId}/alerts`, {
        alert_ids: Array.from(selectedAlerts)
      });

      if (currentInvestigation && currentInvestigation.id === targetInvId) {
        loadInvestigation(res.data);
      }

      fetchInvestigations();
      setSelectedAlerts(new Set());
    } catch (err) {
      console.error("Failed to append alerts", err);
      alert("Failed to update investigation.");
    }
  };

  const onConnect = useCallback((params) => setEdges((eds) => addEdge({
    ...params,
    animated: true,
    style: { stroke: '#00f3ff' },
    markerEnd: { type: MarkerType.ArrowClosed, color: '#00f3ff' }
  }, eds)), [setEdges]);

  const onDragStart = (event, alert) => {
    event.dataTransfer.setData('application/reactflow', JSON.stringify(alert));
    event.dataTransfer.effectAllowed = 'move';
  };

  const onDragOver = useCallback((event) => {
    event.preventDefault();
    event.dataTransfer.dropEffect = 'move';
  }, []);

  const onDrop = useCallback(
    (event) => {
      event.preventDefault();

      if (!reactFlowWrapper.current || !reactFlowInstance) return;

      const reactFlowBounds = reactFlowWrapper.current.getBoundingClientRect();
      const alertDataStr = event.dataTransfer.getData('application/reactflow');

      if (!alertDataStr) return;

      const alertData = JSON.parse(alertDataStr);

      const position = reactFlowInstance.project({
        x: event.clientX - reactFlowBounds.left,
        y: event.clientY - reactFlowBounds.top,
      });

      const newNode = {
        id: `alert-${alertData.id}-${Date.now()}`,
        type: 'deviceNode',
        position,
        data: {
          label: `${alertData.tactic}: ${alertData.name}`,
          icon: 'Workstation', // Default for now
          status: 'compromised'
        },
        className: 'pulsing-node'
      };

      setNodes((nds) => {
        const cleanNodes = nds.map(n => ({ ...n, className: '' }));
        return cleanNodes.concat(newNode);
      });
    },
    [reactFlowInstance, setNodes]
  );

  const handlePredict = async () => {
    if (nodes.length === 0) return;

    // Filter out predicted nodes - only use actual alert nodes for prediction base
    const actualAlertNodes = nodes.filter(n => !n.id.startsWith('pred-'));
    if (actualAlertNodes.length === 0) return;

    const lastNode = actualAlertNodes[actualAlertNodes.length - 1];

    let currentTactic = "Initial Access";
    const labelParts = lastNode.data.label.split(":");
    if (labelParts.length > 1) {
      // Handle multi-tactic labels like "Persistence, Privilege Escalation"
      // Take only the first tactic
      const tactics = labelParts[0].trim().split(',');
      currentTactic = tactics[0].trim();
    } else if (lastNode.data.label === "Firewall") {
      currentTactic = "Initial Access";
    }

    setPredicting(true);
    try {
      const res = await axios.post(`${API_BASE_URL}/predict`, {
        current_tactic: currentTactic,
        n_steps: 1,
        investigation_id: currentInvestigation?.id
      });

      const predictions = res.data.next_tactics;
      if (!predictions || predictions.length === 0) {
        // Provide context-aware messaging for terminal states
        if (currentTactic === "Impact" || currentTactic === "Exfiltration") {
          alert(`Terminal attack stage reached (${currentTactic}). No further progression predicted.`);
        } else {
          alert("No next steps predicted.");
        }
        return;
      }

      const sourceId = lastNode.id;
      const newNodes = [];
      const newEdges = [];

      predictions.forEach((pred, index) => {
        const id = `pred-${Date.now()}-${index}`;
        let targetIcon = 'Activity';

        // Icon mapping primarily (position handling handled by layout now)
        if (pred.target_layer) {
          if (pred.target_layer === "Database") targetIcon = 'Database';
          else if (pred.target_layer === "Web Server") targetIcon = 'Server';
          else if (pred.target_layer === "Firewall") targetIcon = 'Firewall';
        }

        newNodes.push({
          id,
          type: 'deviceNode',
          data: {
            label: `${pred.tactic} (${(pred.probability * 100).toFixed(0)}%)`,
            icon: targetIcon,
            status: 'target',
            huntingQueries: pred.huntingQueries,
            detectionRules: pred.detectionRules,
            description: pred.description,
            contextIOCs: pred.contextIOCs
          },
          position: { x: 0, y: 0 } // Function will calculate this
        });

        newEdges.push({
          id: `e-${sourceId}-${id}`,
          source: sourceId,
          target: id,
          animated: true,
          style: { stroke: '#00f3ff', strokeDasharray: 5 },
          label: 'likely path'
        });
      });

      const allNodes = nodes.concat(newNodes);
      const allEdges = edges.concat(newEdges);

      const { nodes: layoutedNodes, edges: layoutedEdges } = getLayoutedElements(
        allNodes,
        allEdges
      );

      setNodes(layoutedNodes);
      setEdges(layoutedEdges);

    } catch (err) {
      console.error("Prediction failed", err);
      alert("Prediction failed. See console.");
    } finally {
      setPredicting(false);
    }
  };

  const handleAlertAdded = (newAlert) => {
    setAlerts([...alerts, newAlert]);
  };

  const deleteAlert = (id) => {
    const newAlerts = alerts.filter(a => a.id !== id);
    setAlerts(newAlerts);
  };

  const confirmDeleteInvestigation = (e, id) => {
    e.stopPropagation();
    setInvestigationToDelete(id);
    setShowDeleteConfirm(true);
  };

  const handleDeleteConfirmed = async () => {
    if (!investigationToDelete) return;

    const id = investigationToDelete;
    setShowDeleteConfirm(false);
    setInvestigationToDelete(null);

    try {
      setInvestigations(prev => prev.filter(i => i.id !== id));
      if (currentInvestigation && currentInvestigation.id === id) {
        // Switch to home if we deleted the current investigation
        handleGoHome();
      }

      await axios.delete(`${API_BASE_URL}/investigations/${id}`);
    } catch (err) {
      console.error("Failed to delete investigation:", err);
      fetchInvestigations();
      alert("Failed to delete investigation. Server error.");
    }
  };

  const handleNodeClick = useCallback((event, node) => {
    setSelectedNode(node);
  }, []);

  return (
    <div className="app-container" style={{ width: '100vw', height: '100vh', display: 'flex', background: '#000000' }}>
      {showInvestigationModal && (
        <CreateInvestigationModal
          selectedAlertsCount={selectedAlerts.size}
          onClose={() => setShowInvestigationModal(false)}
          onCreate={submitInvestigation}
        />
      )}
      {showAddToInvestigationModal && (
        <AddToInvestigationModal
          onClose={() => setShowAddToInvestigationModal(false)}
          onAdd={addToInvestigation}
          investigations={investigations}
          currentInvestigationId={currentInvestigation?.id}
          selectedCount={selectedAlerts.size}
        />
      )}
      {showModal && (
        <AddAlertModal
          onClose={() => setShowModal(false)}
          onAlertAdded={handleAlertAdded}
        />
      )}
      {showDeleteConfirm && (
        <ConfirmationModal
          title="Delete Investigation?"
          message="This action cannot be undone. The investigation and its graph will be permanently removed."
          confirmText="Delete Forever"
          onConfirm={handleDeleteConfirmed}
          onCancel={() => setShowDeleteConfirm(false)}
        />
      )}

      {/* Sidebar */}
      <div className="card" style={{
        width: isSidebarCollapsed ? '60px' : '340px',
        height: 'calc(100% - 40px)',
        margin: '20px',
        padding: isSidebarCollapsed ? '10px' : '20px',
        display: 'flex',
        flexDirection: 'column',
        zIndex: 10,
        transition: 'all 0.3s ease',
        position: 'relative'
      }}>
        {!isSidebarCollapsed && (
          <>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
              <div
                style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}
                onClick={handleGoHome}
                title="Go to home"
              >
                <ShieldAlert color="var(--primary)" size={28} />
                <h2 style={{ margin: 0, fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)' }}>CyberMaps</h2>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <a
                  href="https://github.com/yourusername/CyberMaps"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="btn-ghost btn-xs"
                  title="Download Docker Version"
                  style={{ color: '#00f3ff', textDecoration: 'none', border: '1px solid #00f3ff', borderRadius: '4px', padding: '2px 6px', fontSize: '0.7rem' }}
                >
                  GET LOCAL
                </a>
                <button
                  className="btn-ghost btn-sm"
                  onClick={() => setIsSidebarCollapsed(true)}
                  title="Collapse sidebar"
                >
                  <ChevronLeft size={18} />
                </button>
              </div>
            </div>
          </>
        )}

        {isSidebarCollapsed && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', alignItems: 'center' }}>
            <button
              className="btn-ghost btn-sm"
              onClick={() => setIsSidebarCollapsed(false)}
              title="Expand sidebar"
            >
              <ChevronRight size={20} />
            </button>

          </div>
        )}

        {!isSidebarCollapsed && (
          <>
            <button
              className="btn btn-primary"
              style={{ marginBottom: '20px', width: '100%', fontSize: '15px', padding: 'var(--space-4) var(--space-6)' }}
              onClick={() => setShowModal(true)}
            >
              <PlusCircle size={18} /> Add Alert
            </button>

            {/* Investigations List */}
            <div style={{ marginBottom: '20px', paddingBottom: '20px', borderBottom: '2px solid var(--border-default)' }}>
              <div style={{ maxHeight: '150px', overflowY: 'auto' }}>
                <h3 style={{ color: '#00f3ff', fontSize: '0.9rem', textTransform: 'uppercase', display: 'flex', alignItems: 'center', gap: '5px' }}>
                  <FileSearch size={14} /> Investigations
                </h3>
                {investigations.length === 0 ? (
                  <p style={{ fontSize: '0.8rem', color: '#666', fontStyle: 'italic' }}>No active investigations.</p>
                ) : (
                  investigations.map(inv => {
                    const isActive = currentInvestigation && currentInvestigation.id === inv.id;
                    return (
                      <div
                        key={inv.id}
                        className="glass-panel"
                        onClick={() => loadInvestigation(inv)}
                        style={{
                          padding: '8px',
                          marginTop: '5px',
                          cursor: 'pointer',
                          borderLeft: isActive ? '4px solid #00f3ff' : '2px solid transparent',
                          background: isActive ? 'rgba(0, 243, 255, 0.1)' : 'rgba(255, 255, 255, 0.05)',
                          boxShadow: isActive ? '0 0 10px rgba(0, 243, 255, 0.2)' : 'none',
                          fontSize: '0.8rem',
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          transition: 'all 0.2s ease'
                        }}
                      >
                        <div>
                          <span style={{ fontWeight: isActive ? 'bold' : 'normal', color: isActive ? '#fff' : '#aaa' }}>{inv.name}</span>
                          <div style={{ fontSize: '0.7rem', color: '#666' }}>
                            {new Date(inv.created_at).toLocaleTimeString()}
                          </div>
                        </div>
                        <Trash2
                          size={14}
                          color="#ff0055"
                          style={{ opacity: 0.7 }}
                          className="hover-bright"
                          onClick={(e) => confirmDeleteInvestigation(e, inv.id)}
                        />
                      </div>
                    );
                  })
                )}
              </div>
            </div>

            {/* Alerts List */}
            <div style={{ marginBottom: '20px', overflowY: 'auto', flex: 1 }}>
              <h3 style={{ color: 'var(--accent-secondary)', fontSize: '0.9rem', textTransform: 'uppercase' }}>Incoming Alerts</h3>
              {alerts.length === 0 ? (
                <p style={{ fontSize: '0.8rem', color: '#666' }}>Loading alerts...</p>
              ) : (
                alerts.map(alert => (
                  <div
                    key={alert.id}
                    className="glass-panel"
                    style={{
                      padding: '10px',
                      marginTop: '10px',
                      borderLeft: `3px solid ${alert.severity === 'Critical' ? 'var(--accent-secondary)' : 'var(--accent-warning)'}`,
                      position: 'relative',
                      background: selectedAlerts.has(alert.id) ? 'rgba(0, 243, 255, 0.1)' : undefined
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', marginBottom: '5px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <div
                          onClick={(e) => {
                            e.stopPropagation();
                            toggleAlertSelection(alert.id);
                          }}
                          onMouseDown={(e) => e.stopPropagation()}
                          style={{ cursor: 'pointer', zIndex: 10 }}
                        >
                          {selectedAlerts.has(alert.id) ? <CheckSquare size={16} color="#00f3ff" /> : <Square size={16} color="#666" />}
                        </div>
                        <span style={{ color: alert.severity === 'Critical' ? 'var(--accent-secondary)' : 'var(--accent-warning)' }}>
                          {alert.tactic.toUpperCase()}
                        </span>
                      </div>
                      <Trash2
                        size={14}
                        style={{ cursor: 'pointer', color: '#ff0055' }}
                        onClick={(e) => {
                          e.stopPropagation();
                          deleteAlert(alert.id);
                        }}
                      />
                    </div>
                    <div
                      draggable
                      onDragStart={(e) => onDragStart(e, alert)}
                      style={{ cursor: 'grab' }}
                    >
                      <p style={{ fontSize: '0.9rem', margin: '5px 0', fontWeight: 'bold' }}>{alert.name}</p>
                      <p style={{ fontSize: '0.7rem', color: '#aaa' }}>{alert.description}</p>
                    </div>
                  </div>
                ))
              )}
            </div>

            <div style={{ marginTop: 'auto', display: 'flex', flexDirection: 'column', gap: '10px' }}>

              <div style={{ display: 'flex', gap: '8px' }}>
                <button
                  className="btn btn-primary"
                  onClick={handleOpenInvestigationModal}
                  disabled={predicting}
                  style={{ flex: 1, fontSize: '14px', padding: 'var(--space-4) var(--space-5)' }}
                >
                  <FileSearch size={16} /> New Inv.
                </button>

                {investigations.length > 0 && (
                  <button
                    className="btn btn-secondary"
                    onClick={handleOpenAddToInvestigation}
                    disabled={predicting || selectedAlerts.size === 0}
                    style={{ flex: 1, fontSize: '14px', padding: 'var(--space-4) var(--space-5)' }}
                  >
                    <PlusCircle size={16} /> Add to...
                  </button>
                )}
              </div>

              <button
                className="btn btn-primary"
                onClick={handlePredict}
                disabled={predicting}
                style={{ width: '100%', fontSize: '15px', padding: 'var(--space-4) var(--space-6)' }}
              >
                {predicting ? "Analyzing..." : "Predict Next Step"}
              </button>
            </div>
          </>
        )}
      </div>

      {/* Main Canvas + Tabs */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
        {/* No TabBar */}
        <div style={{ flex: 1, position: 'relative' }} ref={reactFlowWrapper}>
          {/* Top-right controls */}
          <div style={{ position: 'absolute', top: '20px', right: '20px', display: 'flex', alignItems: 'center', gap: '10px', zIndex: 10 }}>
            {/* Investigation Summary Toggle Button */}
            {currentInvestigation && (
              <button
                onClick={() => setShowInvestigationSummary(!showInvestigationSummary)}
                className="btn-ghost"
                style={{ padding: '8px 15px', fontSize: '0.85rem', border: showInvestigationSummary ? '1px solid #00f3ff' : '1px solid transparent' }}
                title={showInvestigationSummary ? "Hide Investigation Summary" : "Show Investigation Summary"}
              >
                <FileSearch size={16} style={{ marginRight: '5px' }} />
                Summary
              </button>
            )}

            {/* V2 Kill Chain HUD Toggle */}
            <button
              onClick={() => setUseV2Viz(!useV2Viz)}
              className="btn-ghost"
              style={{
                padding: '8px 15px',
                fontSize: '0.85rem',
                border: useV2Viz ? '2px solid #f43f5e' : '1px solid rgba(139, 92, 246, 0.3)',
                background: useV2Viz ? 'rgba(244, 63, 94, 0.1)' : 'transparent',
                boxShadow: useV2Viz ? '0 0 16px rgba(244, 63, 94, 0.4)' : 'none'
              }}
              title={useV2Viz ? "Switch to Classic View" : "Enable Kill Chain HUD"}
            >
              {useV2Viz ? '⚡ KILL CHAIN' : '📊 Classic'}
            </button>


            <div className="glass-panel" style={{ padding: '10px 20px', cursor: 'pointer' }} onClick={() => {
              setNodes(nodes.filter(n => !n.selected));
              setEdges(edges.filter(e => !e.selected));
              setSelectedNode(null);
            }}>
              <Trash2 size={16} color="#ff0055" />
            </div>
          </div>

          <div style={{ width: '100%', height: '100%' }}>

            {/* Strategic View Dashboard */}
            {currentInvestigation === null && (
              <div className="glass-panel" style={{
                position: 'absolute',
                top: '20px',
                left: '20px',
                zIndex: 20,
                padding: '20px',
                pointerEvents: 'none',
                border: '1px solid var(--primary)',
                boxShadow: '0 0 20px rgba(0, 243, 255, 0.2)'
              }}>
                <h4 style={{ margin: '0 0 15px 0', color: '#00f3ff', fontSize: '1rem', letterSpacing: '1px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <ShieldAlert size={18} /> GLOBAL OPS CENTER
                </h4>
                <div style={{ fontSize: '0.9rem', color: '#aaa', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: '20px' }}>
                    <span>Active Investigations:</span>
                    <span style={{ color: '#fff', fontWeight: 'bold' }}>{investigations.length}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: '20px' }}>
                    <span>Incoming Alerts:</span>
                    <span style={{ color: '#ff0055', fontWeight: 'bold' }}>{alerts.length}</span>
                  </div>
                </div>
              </div>
            )}

            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              onConnect={onConnect}
              onInit={setReactFlowInstance}
              onDrop={onDrop}
              onDragOver={onDragOver}
              onNodeClick={handleNodeClick}
              onNodeDoubleClick={handleNodeDoubleClick}
              deleteKeyCode={['Backspace', 'Delete']}
              fitView
              nodeTypes={nodeTypes}
              style={{ background: 'transparent' }}
            >
              <Background color="#aaa" gap={16} size={1} />
              <Controls style={{ fill: '#fff' }} />
            </ReactFlow>
          </div>
        </div>
      </div>

      {/* Investigation Summary Drawer */}
      {
        showInvestigationSummary && (
          <div className={`summary-drawer ${isSummaryCollapsed ? 'collapsed' : ''}`} style={{
            position: 'absolute',
            top: '70px',
            right: '20px',
            width: isSummaryCollapsed ? '40px' : (isSummaryExpanded ? '900px' : '450px'),
            maxHeight: 'calc(100vh - 100px)',
            background: 'rgba(20, 20, 25, 0.95)',
            backdropFilter: 'blur(20px)',
            border: '1px solid var(--glass-border)',
            borderRadius: '12px',
            boxShadow: '0 10px 40px rgba(0,0,0,0.5)',
            zIndex: 100, // Increased z-index
            overflow: 'hidden',
            transition: 'width 0.3s ease',
            display: 'flex',
            flexDirection: 'column'
          }}>
            <div style={{ padding: '10px', borderBottom: '1px solid var(--glass-border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'rgba(255,255,255,0.02)' }}>
              <div style={{ display: 'flex', alignItems: 'center' }}>
                <button className="btn-ghost" onClick={() => setIsSummaryCollapsed(!isSummaryCollapsed)}>
                  {isSummaryCollapsed ? <ChevronLeft size={16} /> : <ChevronRight size={16} />}
                </button>
                {!isSummaryCollapsed && <span style={{ marginLeft: 10, fontSize: '0.8rem', color: '#666', textTransform: 'uppercase', letterSpacing: '1px' }}>Investigation Report</span>}
              </div>

              {!isSummaryCollapsed && (
                <button className="btn-ghost" onClick={() => setIsSummaryExpanded(!isSummaryExpanded)} title={isSummaryExpanded ? "Restore" : "Expand"}>
                  {isSummaryExpanded ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
                </button>
              )}
            </div>
            {!isSummaryCollapsed && (
              <div style={{ flex: 1, overflowY: 'auto', padding: '10px' }}>
                {!investigationSummary ? (
                  <div style={{ color: '#aaa', fontStyle: 'italic', padding: '20px', textAlign: 'center' }}>
                    Loading intelligence...
                  </div>
                ) : investigationSummary.error ? (
                  <div style={{ color: '#ff0055', padding: '20px', textAlign: 'center' }}>
                    {investigationSummary.message}
                  </div>
                ) : (
                  <InvestigationSummary summary={investigationSummary} onClose={() => setShowInvestigationSummary(false)} />
                )}
              </div>
            )}
          </div>
        )
      }

      {/* Node Details Panel */}
      {
        selectedNode && !showPredictionDrawer && (
          <NodeDetailsPanel
            node={selectedNode}
            tacticInfo={tacticInfo}
            onClose={() => setSelectedNode(null)}
          />
        )
      }

      {/* Prediction Drawer - High Z-Index Wrapper */}
      <div style={{ position: 'relative', zIndex: 9999 }}>
        <PredictionDrawer
          isOpen={showPredictionDrawer}
          onClose={() => setShowPredictionDrawer(false)}
          predictionData={predictionData}
        />
      </div>

    </div >
  );
}

export default CyberMapsApp;
