import os
import sys
import socket
import subprocess
import webbrowser
import time
import threading

def find_available_port(preferred_ports=[5050, 8080, 8000, 5001, 8888]):
    """Find a port that is open and not blocked by Windows permissions."""
    for port in preferred_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('127.0.0.1', port))
                return port
        except OSError:
            continue
    # Fallback to system-assigned port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def check_and_install_dependencies():
    required_packages = ["flask", "requests", "reportlab", "dnspython", "urllib3"]
    missing = []
    
    for pkg in required_packages:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
            
    if missing:
        print(f"[*] Installing required libraries: {', '.join(missing)}...")
        req_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "requirements.txt")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", req_path])
            print("[+] All dependencies installed successfully!\n")
        except Exception as e:
            print(f"[!] Note: Automatic pip install encountered: {e}")
            print(f"[!] Please run manually: pip install -r requirements.txt\n")

def main():
    print("=" * 65)
    print("   ConfigScore: Website Security Scanner & Remediation Solver   ")
    print("   Website Security Scanner")
    print("=" * 65)
    
    check_and_install_dependencies()

    # Find a free port (avoids Windows port 5000 socket restriction)
    port = find_available_port([5050, 8080, 8000, 5001, 8888])
    url = f"http://127.0.0.1:{port}"

    print(f"\n[*] Starting ConfigScore Web Server on port {port}...")
    print(f"[*] Website URL: {url}")
    print("[+] Press Ctrl+C in this terminal to stop the server.\n")

    # Automatically open the browser to the working port
    def open_browser():
        time.sleep(1.2)
        webbrowser.open(url)

    threading.Thread(target=open_browser, daemon=True).start()

    # Run the main Flask application on the available port
    from app import app
    app.run(host="127.0.0.1", port=port, debug=False)

if __name__ == "__main__":
    main()
