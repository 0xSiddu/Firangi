import json
import os
from pathlib import Path
from http.server import SimpleHTTPRequestHandler, HTTPServer
import urllib.parse
import sys

PORT = 8000
RESULTS_DIR = Path("results")

class DashboardHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        # API endpoint to list available scan results
        if self.path == '/api/scans':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            scans = []
            if RESULTS_DIR.exists():
                for f in sorted(RESULTS_DIR.glob('scan_*.json'), reverse=True):
                    # skip summary files
                    if 'summary' in f.name:
                        continue
                    scans.append(f.name)
                # Ensure live scan is always first if it exists
                if (RESULTS_DIR / 'live_scan.json').exists():
                    if 'live_scan.json' in scans:
                        scans.remove('live_scan.json')
                    scans.insert(0, 'live_scan.json')
            
            self.wfile.write(json.dumps(scans).encode('utf-8'))
            return
            
        # API endpoint to get a specific scan result
        elif self.path.startswith('/api/scan/'):
            filename = urllib.parse.unquote(self.path.split('/')[-1])
            filepath = RESULTS_DIR / filename
            
            if filepath.exists() and filepath.parent == RESULTS_DIR:
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                
                with open(filepath, 'rb') as f:
                    self.wfile.write(f.read())
            else:
                self.send_response(404)
                self.end_headers()
            return
            
        # Serve static files as usual
        return super().do_GET()

    def do_POST(self):
        if self.path == '/api/update-status':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            try:
                data = json.loads(post_data.decode('utf-8'))
                filename = data.get('filename')
                finding_index = data.get('index')
                new_status = data.get('status') # true = valid, false = invalid, null = unverified
                
                if filename and finding_index is not None:
                    filepath = RESULTS_DIR / filename
                    
                    if filepath.exists() and filepath.parent == RESULTS_DIR:
                        with open(filepath, 'r') as f:
                            scan_data = json.load(f)
                            
                        if 0 <= finding_index < len(scan_data.get('findings', [])):
                            scan_data['findings'][finding_index]['Verified'] = new_status
                            # Also add a manual override flag so the backend knows
                            scan_data['findings'][finding_index]['ManualOverride'] = True
                            
                            with open(filepath, 'w') as f:
                                json.dump(scan_data, f, indent=2)
                                
                            self.send_response(200)
                            self.send_header('Content-type', 'application/json')
                            self.end_headers()
                            self.wfile.write(json.dumps({"success": True}).encode('utf-8'))
                            return
            except Exception as e:
                print(f"Error updating status: {e}")
                
            self.send_response(400)
            self.end_headers()
            return

def start_server():
    try:
        with HTTPServer(("", PORT), DashboardHandler) as httpd:
            print(f"Server started at http://localhost:{PORT}")
            httpd.serve_forever()
    except OSError as e:
        if e.errno == 98:
            print(f"Port {PORT} is already in use. Dashboard should already be accessible.")
        else:
            raise

if __name__ == '__main__':
    start_server()
