import os
import json
import re
from typing import List, Dict, Any
from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()

# Model utama yang digunakan
PRIMARY_MODEL = "gemini-3-flash-preview"

def _build_prompt(analysis: Dict[str, Any]) -> str:
    summary = analysis.get('summary', {})
    alerts = analysis.get('alerts', [])

    attack_types = summary.get('attack_types', {})
    protocols = summary.get('protocols', {})
    total_packets = summary.get('total_packets', 0)
    total_alerts = summary.get('total_alerts', 0)

    # Ambil top 5 attack types
    top_attacks = sorted(attack_types.items(), key=lambda x: x[1], reverse=True)[:5]

    # Ambil contoh 5 alert untuk konteks
    sample_alerts = alerts[:5]

    return (
        "You are a seasoned cyber security analyst and senior blue-team security engineer. "
        "Based on the network analysis summary below, produce at least 10 and up to 14 "
        "prioritized, actionable recommendations tailored to the observed threats. "
        "Each item MUST be a single-line numbered sentence: start with a short action title, "
        "then a colon, followed by condensed technical steps with command/config examples "
        "separated by ' | ', and finish with a quick validation hint. Output plain text only "
        "(no markdown or code blocks). Keep each item under ~220 chars. Be context-aware and "
        "reference relevant artifacts (IPs, protocols, rules). Prefer environment-agnostic steps "
        "(Linux iptables/firewall-cmd, Windows Firewall, Cisco ACL; IDS rules like Suricata/Snort) "
        "and SIEM queries. If there are high-severity signals (e.g., DoS, brute force), "
        "prioritize containment steps. Number each item 1..N.\n\n"
        f"Total packets: {total_packets}\n"
        f"Total alerts: {total_alerts}\n"
        f"Protocols count: {json.dumps(protocols)}\n"
        f"Top attack types: {json.dumps(top_attacks)}\n"
        f"Sample alerts: {json.dumps(sample_alerts)}\n"
        "Format each item like: 'N. <Title>: <Steps a> | <Steps b> | <Steps c> | Validate: <hint>'."
    )

def _split_recommendations(text: str) -> List[str]:
    if not text:
        return []
    
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    recs: List[str] = []
    # Pattern to match numbers like "1. ", "2) ", etc.
    bullet_pattern = re.compile(r"^\s*(?:\d+[\).\s-]|[-*•])\s+")

    for l in lines:
        if bullet_pattern.match(l):
            item = bullet_pattern.sub('', l).strip()
            if item and not item.upper().startswith("ERROR:"):
                recs.append(item)
        else:
            # Fallback split by sentences if not bulleted
            sentences = re.split(r"(?<=[.!?])\s+", l)
            for s in sentences:
                s = s.strip()
                if s and not s.upper().startswith("ERROR:"):
                    recs.append(s)

    # Deduplicate while preserving order
    seen = set()
    deduped: List[str] = []
    for r in recs:
        key = r.lower()
        if key not in seen:
            seen.add(key)
            deduped.append(r)
    return deduped[:14]

def generate_ai_recommendations(analysis: Dict[str, Any]) -> Dict[str, Any]:
    api_key = os.getenv('GEMINI_API_KEY')
    if not api_key:
        return {'status': 'error', 'message': 'Missing GEMINI_API_KEY', 'recommendations': []}

    try:
        # Konfigurasi SDK
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(PRIMARY_MODEL)
        
        prompt = _build_prompt(analysis or {})
        
        # Panggilan AI menggunakan SDK (Metode paling stabil)
        response = model.generate_content(
            prompt,
            generation_config={
                "temperature": 0.7,
                "top_k": 40,
                "top_p": 0.95,
                "max_output_tokens": 1024,
            }
        )
        
        text = response.text if response else ""
        recs = _split_recommendations(text)

        if not recs:
            # Fallback jika AI gagal memberikan hasil
            return {
                'status': 'success',
                'message': 'ai_fallback_triggered',
                'recommendations': [
                    'Enable SIEM correlation for detected attack types and top source IPs',
                    'Harden exposed services and apply rate limiting on suspected endpoints',
                    'Increase monitoring for protocols with highest anomaly counts',
                    'Segment network to isolate frequently targeted destinations',
                ]
            }

        return {'status': 'success', 'recommendations': recs}

    except Exception as e:
        return {'status': 'error', 'message': str(e), 'recommendations': []}

# Fungsi internal untuk kebutuhan diagnostik/proxy (jika dipanggil dari app.py)
def _call_gemini_with_diag(prompt: str, api_key: str) -> Dict[str, Any]:
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(PRIMARY_MODEL)
        resp = model.generate_content(prompt)
        return {
            "text": resp.text,
            "endpoint": f"sdk:{PRIMARY_MODEL}",
            "status_code": 200,
            "has_text_parts": True
        }
    except Exception as e:
        return {"text": "", "status_code": 500, "message": str(e)}
