from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Dict, Any
from ai_engine import ai_engine
from core.repository import AlertRepository
# We need to import the dependency to get the repo.
# Ideally this dependency is in a shared module or main. 
# For now, we will assume we can import it from main or redefine it.
# To avoid circular imports, let's inject strictly.

router = APIRouter(prefix="/api/simulation", tags=["simulation"])

class SimulationRequest(BaseModel):
    prompt: str

@router.post("/generate")
async def generate_simulation(request: SimulationRequest):
    """
    Generate a simulated attack scenario based on a prompt.
    Returns the generated alerts but does NOT store them automatically 
    (unless we decide to strictly store them in the InMemory repo for the session).
    
    For the "Playground" experience, the frontend might want to receive them 
    and then "replay" them one by one to the POST /alerts endpoint, or 
    we can store them here in the repo.
    
    Decision: Return them to frontend so the "Playground" can visualize the "Incoming" stream.
    """
    try:
        alerts = await ai_engine.generate_attack_simulation(request.prompt)
        return {"alerts": alerts}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
