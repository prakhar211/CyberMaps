
import os
from dotenv import load_dotenv

load_dotenv()
import json
import re
from typing import List, Dict, Any, Optional
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import PydanticOutputParser
from pydantic import BaseModel, Field

# --- Data Models for Output Parsing ---

class HuntingQuery(BaseModel):
    platform: str = Field(description="The platform for the query (e.g., Splunk, KQL, Grep)")
    query: str = Field(description="The actual query string")
    description: str = Field(description="Explanation of what the query looks for")

class DetectionRule(BaseModel):
    format: str = Field(description="Format of the rule (e.g., Sigma, YARA)")
    rule: str = Field(description="The rule content")
    description: str = Field(description="Description of what the rule detects")

class ContextIOC(BaseModel):
    type: str = Field(description="Type of IOC (e.g., IP, Hash, User)")
    value: str = Field(description="The IOC value")
    source: str = Field(description="Where this IOC was observed in the context")

class ThreatIntelResponse(BaseModel):
    huntingQueries: List[HuntingQuery] = Field(description="List of seeking queries")
    detectionRules: List[DetectionRule] = Field(description="List of detection rules")
    description: str = Field(description="Strategic analysis of the predicted tactic")
class SimulatedAlert(BaseModel):
    name: str = Field(description="Name of the alert")
    severity: str = Field(description="Severity: Low, Medium, High, or Critical")
    tactic: str = Field(description="MITRE Tactic name (e.g. Initial Access)")
    technique: Optional[str] = Field(description="MITRE Technique name")
    description: str = Field(description="Brief description of the event")
    raw_data: Dict[str, Any] = Field(description="Synthetic raw log data (JSON) to make it look authentic")

class SimulationResponse(BaseModel):
    alerts: List[SimulatedAlert] = Field(description="Ordered list of alerts representing the attack chain")

# --- AI Engine ---

class AIEngine:
    def __init__(self):
        self.api_key = os.getenv("GOOGLE_API_KEY")
        if not self.api_key:
            print("WARNING: GOOGLE_API_KEY not found. AI features will return mock data.")
            self.llm = None
        else:
            self.llm = ChatGoogleGenerativeAI(model="gemini-flash-latest", temperature=0.7, google_api_key=self.api_key)

    def sanitize_context(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Redact sensitive PII from alert raw data before sending to LLM.
        Keeps IPs and Usernames as they are critical for context, but would redact 
        things like 'password', 'secret', or known PII patterns if strict mode was on.
        For now, we implement a basic pass that ensures no huge blobs are sent.
        """
        sanitized = []
        for alert in alerts:
            # Deep copy to avoid modifying original
            s_alert = alert.copy()
            raw = s_alert.get("raw_data", {})
            
            # Simple redaction of obvious secret keys
            if raw:
                str_raw = json.dumps(raw)
                # Regex to mask common keys like "password": "..."
                str_raw = re.sub(r'"password"\s*:\s*"[^"]+"', '"password": "[REDACTED]"', str_raw, flags=re.IGNORECASE)
                str_raw = re.sub(r'"secret"\s*:\s*"[^"]+"', '"secret": "[REDACTED]"', str_raw, flags=re.IGNORECASE)
                str_raw = re.sub(r'"key"\s*:\s*"[^"]+"', '"key": "[REDACTED]"', str_raw, flags=re.IGNORECASE)
                
                s_alert["raw_data"] = json.loads(str_raw)
            
            sanitized.append(s_alert)
        return sanitized

    async def generate_hunting_intel(self, current_tactic: str, predicted_tactic: str, alerts_context: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generates threat hunting content for the predicted tactic.
        """
        # 0. Fail fast if no key
        if not self.llm:
            return self._get_mock_response(predicted_tactic)

        # 1. Sanitize Context
        clean_alerts = self.sanitize_context(alerts_context)
        
        # Limit context size - take last 5 alerts max
        start_idx = max(0, len(clean_alerts) - 5)
        recent_activity = clean_alerts[start_idx:]

        # 2. Build Prompt
        system_prompt = """You are an elite Cyber Threat Hunter and Detection Engineer. 
        Your goal is to analyze an active intrusion context and predict/generate specific hunting queries and rules for the NEXT LIKELY PHASE.
        
        The current attack phase is: {current_tactic}
        The predicted next phase is: {predicted_tactic}
        
        You MUST return valid JSON that matches the following schema exactly:
        {format_instructions}
        """

        user_template = """
        Here is the recent alert activity (Context):
        {context_json}
        
        Based on this specific user, host, and observed behavior:
        1. Explain WHY {predicted_tactic} is the likely next step (populate 'description').
        2. Generate 2-3 specific Splunk or KQL queries (populate 'huntingQueries').
           CRITICAL: You MUST use the actual values from the context in your queries where applicable.
           - If a specific Username is in context, filter by `User="<actual_username>"`.
           - If a specific IP is involved, filter by `SrcIp="<actual_ip>"`.
        3. Generate a SIGMA rule (populate 'detectionRules').
        4. Extract relevant IOCs from the context (populate 'contextIOCs').
        """
        
        parser = PydanticOutputParser(pydantic_object=ThreatIntelResponse)

        prompt = ChatPromptTemplate.from_messages([
            ("system", system_prompt),
            ("user", user_template)
        ]).partial(format_instructions=parser.get_format_instructions())
        
        chain = prompt | self.llm | parser
        
        try:
            # 3. Invoke
            result = await chain.ainvoke({
                "current_tactic": current_tactic,
                "predicted_tactic": predicted_tactic,
                "context_json": json.dumps(recent_activity, indent=2, default=str)
            })
            
            return result.model_dump()
            
        except Exception as e:
            print(f"AI Generation Error: {e}")
            return self._get_mock_response(predicted_tactic, error=str(e))

    async def generate_attack_simulation(self, user_prompt: str) -> List[Dict[str, Any]]:
        """
        Generates a sequence of simulated alerts based on a user description.
        """
        if not self.llm:
            print("AI Engine not initialized with key. Returning empty simulation.")
            return []

        system_prompt = """You are a Red Team Expert and Attack Simulator.
        Your goal is to generate a realistic, multi-step cyberattack kill chain based on the user's scenario.
        
        You MUST return a JSON object with a list of 'alerts'.
        Each alert must strictly follow the schema:
        {format_instructions}
        
        GUIDELINES:
        1. The alerts should form a logical progression (e.g., Phishing -> Execution -> Persistence -> C2).
        2. Use MITRE ATT&CK Tactic names strictly (e.g., 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Command and Control', 'Exfiltration', 'Impact').
        3. 'raw_data' should contain realistic-looking fields (Source IP, User, Process Name, CommandLine, FilePath) relevant to the alert.
        4. Generate between 5 and 10 alerts for the scenario.
        """

        user_template = "Scenario: {user_prompt}"

        parser = PydanticOutputParser(pydantic_object=SimulationResponse)

        prompt = ChatPromptTemplate.from_messages([
            ("system", system_prompt),
            ("user", user_template)
        ]).partial(format_instructions=parser.get_format_instructions())

        chain = prompt | self.llm | parser

        try:
            result = await chain.ainvoke({"user_prompt": user_prompt})
            return [alert.model_dump() for alert in result.alerts]
        except Exception as e:
            print(f"AI Simulation Error: {e}")
            # Fallback or re-raise depending on strategy. For now return empty or error.
            raise e

    def _get_mock_response(self, predicted_tactic: str, error: str = "") -> Dict[str, Any]:
        """Fallback mock data if AI fails or no key provided"""
        msg = f"AI Generation Unavailable (Missing Key). Showing static template for {predicted_tactic}."
        if error:
            msg = f"AI Generation Failed: {error}. Showing fallback."
            
        return {
            "huntingQueries": [
                {
                    "platform": "Manual Fallback",
                    "query": f"index=* tag={predicted_tactic} | stats count by dest_ip",
                    "description": "Standard hunting query (AI unavailable)"
                }
            ],
            "detectionRules": [],
            "description": msg,
            "contextIOCs": []
        }

# Singleton
ai_engine = AIEngine()
