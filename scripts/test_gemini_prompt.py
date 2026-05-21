import os
import sys
import json
import requests
from dotenv import load_dotenv


def build_prompt_from_analysis(analysis: dict) -> str:
    summary = analysis.get('summary', {})
    alerts = analysis.get('alerts', [])

    attack_types = summary.get('attack_types', {})
    protocols = summary.get('protocols', {})
    total_packets = summary.get('total_packets', 0)
    total_alerts = summary.get('total_alerts', 0)

    top_attacks = sorted(attack_types.items(), key=lambda x: x[1], reverse=True)[:5]
    sample_alerts = alerts[:5]

    return (
        "You are a seasoned cyber security analyst. Based on the network "
        "analysis summary below, generate up to 8 prioritized, actionable "
        "security recommendations tailored to the observed threats. Each "
        "recommendation should be concise (one sentence), specific, and "
        "mapped to concrete actions (controls, monitoring, hardening). "
        "Avoid generic advice; be context-aware and reference relevant "
        "artifacts (IPs, protocols, rules) when helpful. Use a numbered list.\n\n"
        f"Total packets: {total_packets}\n"
        f"Total alerts: {total_alerts}\n"
        f"Protocols count: {json.dumps(protocols)}\n"
        f"Top attack types: {json.dumps(top_attacks)}\n"
        f"Sample alerts: {json.dumps(sample_alerts)}\n"
        "If there are high-severity signals (e.g., DoS, brute force), prioritize containment steps."
    )


def main():
    if len(sys.argv) < 2:
        print("Usage: python scripts/test_gemini_prompt.py <analysis.json> [api_key]")
        sys.exit(1)

    analysis_path = sys.argv[1]
    with open(analysis_path, 'r', encoding='utf-8') as f:
        analysis = json.load(f)

    load_dotenv()
    api_key = os.getenv("GEMINI_API_KEY") or (sys.argv[2] if len(sys.argv) > 2 else None)
    if not api_key:
        print("ERROR: GEMINI_API_KEY not found in environment or argv.")
        sys.exit(1)

    prompt = build_prompt_from_analysis(analysis)

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key={api_key}"
    payload = {
        "contents": [
            {"role": "user", "parts": [{"text": prompt}]}
        ],
        "generationConfig": {
            "temperature": 0.6,
            "topK": 40,
            "topP": 0.95,
            "maxOutputTokens": 512
        },
        "safetySettings": [
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"}
        ]
    }

    resp = requests.post(url, json=payload, timeout=20)
    print("Status:", resp.status_code)
    if 200 <= resp.status_code < 300:
        data = resp.json()
        cand = (data or {}).get("candidates", [])
        if cand:
            parts = cand[0].get("content", {}).get("parts", [])
            texts = [p.get("text") for p in parts if isinstance(p, dict) and p.get("text")]
            if texts:
                print("SUCCESS: Received text\n---\n", "\n".join(texts))
                sys.exit(0)
            else:
                print("EMPTY: No text parts")
        else:
            print("EMPTY: No candidates")
    else:
        try:
            print("ERROR:", json.dumps(resp.json(), indent=2))
        except Exception:
            print("ERROR (non-JSON):", resp.text[:500])
    sys.exit(2)


if __name__ == "__main__":
    main()