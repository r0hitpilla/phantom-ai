"""
PHANTOM AI — Development Runner
Loads .env file and starts the Flask development server.
"""

import os

# Load .env if python-dotenv is available
try:
    from dotenv import load_dotenv
    load_dotenv()
    print("[PHANTOM AI] .env file loaded")
except ImportError:
    print("[PHANTOM AI] python-dotenv not installed — using environment variables directly")

from app import app

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

    print(f"""
╔═══════════════════════════════════════════════╗
║            PHANTOM AI — Red Team Platform      ║
║     FOR AUTHORIZED SECURITY TESTING ONLY       ║
╠═══════════════════════════════════════════════╣
║  URL:       http://localhost:{port:<5}              ║
║  Username:  admin                              ║
║  Password:  {os.environ.get("PHANTOM_PASSWORD","phantom2024"):<35} ║
║  API Key:   {"✓ SET" if os.environ.get("ANTHROPIC_API_KEY") else "✗ NOT SET (demo mode)"}                         ║
╚═══════════════════════════════════════════════╝
""")

    app.run(host="0.0.0.0", port=port, debug=debug, threaded=True)
