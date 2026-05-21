import os
import sys
import json
import requests
from dotenv import load_dotenv


def main():
    """Simple generateContent test with flash-latest and v1beta fallback."""
    load_dotenv()

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key and len(sys.argv) > 1:
        api_key = sys.argv[1]
    if not api_key:
        print("ERROR: GEMINI_API_KEY not found in environment or argv.")
        sys.exit(1)

    endpoints = [
        f"https://generativelanguage.googleapis.com/v1/models/gemini-flash-latest:generateContent?key={api_key}",
        f"https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key={api_key}",
    ]

    payload = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": "Say hello in one sentence"}]
            }
        ],
        "generationConfig": {
            "temperature": 0.7,
            "topK": 40,
            "topP": 0.95,
            "maxOutputTokens": 64
        },
        "safetySettings": [
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"}
        ]
    }

    last_error = None
    for url in endpoints:
        print(f"Testing generateContent: {url}")
        try:
            resp = requests.post(url, json=payload, timeout=15)
            print(f"Status: {resp.status_code}")
            if 200 <= resp.status_code < 300:
                data = resp.json()
                cand = (data or {}).get("candidates", [])
                if cand:
                    parts = cand[0].get("content", {}).get("parts", [])
                    text = None
                    for p in parts:
                        if p.get("text"):
                            text = p["text"]
                            break
                    if text:
                        print("SUCCESS: Received text →", text)
                        sys.exit(0)
                    else:
                        print("EMPTY: No text in candidates; trying next endpoint...")
                        continue
                else:
                    print("EMPTY: No candidates returned; trying next endpoint...")
                    continue
            else:
                try:
                    err = resp.json().get("error", {})
                    last_error = err
                    print("ERROR: ", json.dumps(err, indent=2))
                except Exception:
                    last_error = {"status": resp.status_code, "body": resp.text[:200]}
                continue
        except requests.RequestException as e:
            last_error = {"exception": str(e)}
            print("NETWORK ERROR:", e)
            continue

    print("FAILED: All endpoints tried.")
    if last_error:
        print("Last error:", json.dumps(last_error, indent=2))
    sys.exit(2)


if __name__ == "__main__":
    main()