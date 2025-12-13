import numpy as np
from typing import List, Tuple

# MITRE ATT&CK Tactics in logical order
TACTICS = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact"
]

TACTIC_TO_INDEX = {t: i for i, t in enumerate(TACTICS)}
INDEX_TO_TACTIC = {i: t for i, t in enumerate(TACTICS)}

# Terminal tactics that represent the end of an attack progression
TERMINAL_TACTICS = ["Impact", "Exfiltration"]

class AttackPathPredictor:
    def __init__(self):
        self.transition_matrix = self._build_transition_matrix()

    def _build_transition_matrix(self) -> np.ndarray:
        # Initialize a basic forward-biased transition matrix
        # Each step has high prob of moving to next logical step, 
        # small prob of skipping, small prob of staying.
        size = len(TACTICS)
        matrix = np.zeros((size, size))

        for i in range(size):
            # Self loop (staying in same phase)
            matrix[i][i] = 0.1
            
            # Next phase (most likely)
            if i + 1 < size:
                matrix[i][i+1] = 0.6
            
            # Skip one phase
            if i + 2 < size:
                matrix[i][i+2] = 0.2
            
            # Skip two phases
            if i + 3 < size:
                matrix[i][i+3] = 0.1

        # Normalize rows to sum to 1
        for i in range(size):
            row_sum = np.sum(matrix[i])
            if row_sum > 0:
                matrix[i] = matrix[i] / row_sum
        
        return matrix

    def predict_next(self, current_tactic: str, top_k: int = 3) -> List[Tuple[str, float]]:
        # Handle multi-tactic strings (e.g., "Persistence, Privilege Escalation")
        # Take the first tactic as the primary one for prediction
        if ',' in current_tactic:
            tactics = [t.strip() for t in current_tactic.split(',')]
            current_tactic = tactics[0]
        
        # Check if this is a terminal tactic (end of attack progression)
        if current_tactic in TERMINAL_TACTICS:
            return []  # No further predictions for terminal states
        
        if current_tactic not in TACTIC_TO_INDEX:
            return []

        idx = TACTIC_TO_INDEX[current_tactic]
        probs = self.transition_matrix[idx]
        
        # Get top indices
        top_indices = np.argsort(probs)[::-1][:top_k]
        
        results = []
        for next_idx in top_indices:
            prob = probs[next_idx]
            if prob > 0:
                results.append((INDEX_TO_TACTIC[next_idx], float(prob)))
        
        return results

# Singleton instance
predictor = AttackPathPredictor()
