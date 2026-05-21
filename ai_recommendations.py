import os
import json
import requests
import re
from typing import List, Dict, Any
from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()

# Kandidat endpoint dan model untuk mencoba berbagai versi/API
ENDPOINT_CANDIDATES = [
    # Prefer gemini-1.5-flash variants on v1beta (commonly available)
    "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent",
    "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent",
]


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
        "Prefer environment-agnostic steps (Linux iptables/firewall-cmd, Windows Firewall, "
        "Cisco ACL, IDS rules like Suricata/Snort), and SIEM queries. Reference IPs, "
        "protocols, and relevant rules if available. "
        "Format each item like: 'N. <Title>: <Steps a> | <Steps b> | <Steps c> | Validate: <hint>'."
    )


def _call_gemini(prompt: str, api_key: str) -> str:
    for endpoint in ENDPOINT_CANDIDATES:
        try:
            url = f"{endpoint}?key={api_key}"
            # Build payload; response_mime_type supported on v1beta
            generation = {
                "temperature": 0.7,
                "topK": 40,
                "topP": 0.95,
                "maxOutputTokens": 512
            }
            if "/v1beta/" in endpoint:
                generation["response_mime_type"] = "text/plain"
            payload = {
                "contents": [
                    {"role": "user", "parts": [{"text": prompt}]}
                ],
                "generationConfig": generation,
                "safetySettings": [
                    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"}
                ]
            }
            resp = requests.post(url, json=payload, timeout=20)
            if 200 <= resp.status_code < 300:
                data = resp.json()
                candidates = data.get("candidates", [])
                if not candidates:
                    continue
                content = candidates[0].get("content", {})
                parts = content.get("parts", [])
                # Aggregate all text fragments in order
                texts = [p.get("text") for p in parts if isinstance(p, dict) and p.get("text")]
                if texts:
                    return "\n".join(texts)
                continue
            # non-2xx: try next endpoint
            continue
        except requests.RequestException:
            # network or timeout: try next endpoint
            continue
    # All endpoints failed
    return ""


def _serialize_prompt_feedback(pf: Any) -> Any:
    """Safely serialize SDK PromptFeedback object to JSON-friendly dict.

    Returns a dict with keys 'block_reason' and 'safety_ratings' or a simple
    string/None when detailed fields are unavailable. This prevents Flask
    jsonify errors like: 'Object of type PromptFeedback is not JSON serializable'.
    """
    try:
        if pf is None:
            return None
        # Extract common attributes present in google-generativeai SDK objects
        block_reason = getattr(pf, "block_reason", None)
        ratings = getattr(pf, "safety_ratings", None) or []
        safety_ratings = []
        try:
            for r in ratings:
                safety_ratings.append({
                    "category": getattr(r, "category", None),
                    "probability": getattr(r, "probability", None),
                    "blocked": getattr(r, "blocked", None),
                })
        except Exception:
            # If not iterable or unexpected structure, fall back to string
            safety_ratings = []
        return {"block_reason": block_reason, "safety_ratings": safety_ratings}
    except Exception:
        # As a last resort, return string representation
        try:
            return dict(pf)
        except Exception:
            return str(pf)


def _call_gemini_with_diag(prompt: str, api_key: str) -> Dict[str, Any]:
    """Call Gemini and provide diagnostics along with text.

    Returns dict with keys: text, endpoint, status_code, blocked_reason,
    candidates_count, has_text_parts, prompt_feedback.
    """
    # First, try official Python SDK for better compatibility
    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        # Use flash family as requested/reference
        sdk_model_name = "gemini-2.0-flash"
        model = genai.GenerativeModel(sdk_model_name)
        resp = model.generate_content(
            prompt,
            generation_config={
                "temperature": 0.6,
                "top_k": 40,
                "top_p": 0.95,
                "max_output_tokens": 512,
            },
            safety_settings=[
                {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
            ]
        )
        text = getattr(resp, "text", "") or ""
        pf_json = _serialize_prompt_feedback(getattr(resp, "prompt_feedback", None))
        diag_sdk: Dict[str, Any] = {
            "text": text,
            "endpoint": f"sdk:{sdk_model_name}",
            "status_code": 200 if text else 200,
            "blocked_reason": None,
            "candidates_count": 1 if text else 0,
            "has_text_parts": bool(text),
            "prompt_feedback": pf_json,
        }
        if text:
            return diag_sdk
        # if SDK returned empty, fall through to REST for another attempt
    except Exception as e:
        # SDK not installed or failed – continue to REST with diagnostics
        pass

    diag: Dict[str, Any] = {
        "text": "",
        "endpoint": None,
        "status_code": None,
        "blocked_reason": None,
        "candidates_count": 0,
        "has_text_parts": False,
        "prompt_feedback": None,
    }

    for endpoint in ENDPOINT_CANDIDATES:
        try:
            url = f"{endpoint}?key={api_key}"
            generation = {
                "temperature": 0.7,
                "topK": 40,
                "topP": 0.95,
                "maxOutputTokens": 512
            }
            if "/v1beta/" in endpoint:
                generation["response_mime_type"] = "text/plain"
            payload = {
                "contents": [
                    {"role": "user", "parts": [{"text": prompt}]}
                ],
                "generationConfig": generation,
                "safetySettings": [
                    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"}
                ]
            }
            resp = requests.post(url, json=payload, timeout=20)
            diag.update({"endpoint": endpoint, "status_code": resp.status_code})
            if 200 <= resp.status_code < 300:
                data = resp.json() or {}
                diag["prompt_feedback"] = data.get("promptFeedback")
                candidates = data.get("candidates", [])
                diag["candidates_count"] = len(candidates)
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    texts = [p.get("text") for p in parts if isinstance(p, dict) and p.get("text")]
                    diag["has_text_parts"] = bool(texts)
                    if texts:
                        diag["text"] = "\n".join(texts)
                        return diag
                    # capture block reason if present
                    pf = data.get("promptFeedback") or {}
                    diag["blocked_reason"] = pf.get("blockReason") or pf.get("safetyRatings")
                    # try next endpoint
                    continue
                else:
                    pf = data.get("promptFeedback") or {}
                    diag["blocked_reason"] = pf.get("blockReason") or pf.get("safetyRatings")
                    continue
            else:
                # non-2xx: try next endpoint
                try:
                    err = resp.json().get("error")
                    if err:
                        diag["blocked_reason"] = err
                except Exception:
                    pass
                continue
        except requests.RequestException:
            # network or timeout: try next endpoint
            diag.update({"status_code": None})
            continue

    return diag


def _split_recommendations(text: str) -> List[str]:
    if not text:
        return []
    if text.strip().upper().startswith("ERROR:"):
        return []
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    recs: List[str] = []
    bullet_pattern = re.compile(r"^\s*(?:\d+[\).\s-]|[-*•])\s+")

    for l in lines:
        if bullet_pattern.match(l):
            item = bullet_pattern.sub('', l).strip()
            if item and not item.upper().startswith("ERROR:"):
                recs.append(item)
        else:
            sentences = re.split(r"(?<=[.!?])\s+", l)
            for s in sentences:
                s = s.strip()
                if s and not s.upper().startswith("ERROR:"):
                    recs.append(s)

    # Deduplicate while preserving order, then cap at 8
    seen = set()
    deduped: List[str] = []
    for r in recs:
        key = r.lower()
        if key not in seen:
            seen.add(key)
            deduped.append(r)
    return deduped[:8]


def generate_ai_recommendations(analysis: Dict[str, Any]) -> Dict[str, Any]:
    api_key = os.getenv('GEMINI_API_KEY')
    if not api_key:
        return {
            'status': 'error',
            'message': 'Missing GEMINI_API_KEY',
            'recommendations': []
        }
    try:
        prompt = _build_prompt(analysis or {})
        text = _call_gemini(prompt, api_key)
        recs = _split_recommendations(text)
        if not recs:
            # Fallback jika model tidak mengembalikan teks yang dapat dipecah
            recs = [
                'Enable SIEM correlation for detected attack types and top source IPs',
                'Harden exposed services and apply rate limiting on suspected endpoints',
                'Increase monitoring for protocols with highest anomaly counts',
                'Segment network to isolate frequently targeted destinations',
            ]
            return {
                'status': 'success',
                'message': 'ai_fallback_empty_or_blocked',
                'recommendations': recs
            }
        return {
            'status': 'success',
            'recommendations': recs
        }
    except Exception as e:
        return {
            'status': 'error',
            'message': str(e),
            'recommendations': []
        }