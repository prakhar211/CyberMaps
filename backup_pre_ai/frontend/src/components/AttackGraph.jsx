import React from 'react';
import ReactFlow, {
    Controls,
    Background
} from 'reactflow';
import 'reactflow/dist/style.css';

export default function AttackGraph({
    nodes,
    edges,
    onNodesChange,
    onEdgesChange,
    onConnect,
    onInit,
    onDrop,
    onDragOver,
    nodeTypes,
    onNodeDoubleClick
}) {
    return (
        <div style={{ width: '100%', height: '100%' }}>
            <ReactFlow
                nodes={nodes}
                edges={edges}
                onNodesChange={onNodesChange}
                onEdgesChange={onEdgesChange}
                onConnect={onConnect}
                onInit={onInit}
                onDrop={onDrop}
                onDragOver={onDragOver}
                onNodeDoubleClick={onNodeDoubleClick}
                deleteKeyCode={['Backspace', 'Delete']}
                fitView
                nodeTypes={nodeTypes}
                style={{ background: 'transparent' }}
            >
                <Background color="#aaa" gap={16} size={1} />
                <Controls style={{ fill: '#fff' }} />
            </ReactFlow>
        </div>
    );
}
