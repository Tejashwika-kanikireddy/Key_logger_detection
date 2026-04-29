from flask import Flask, render_template, jsonify, request
from detector.process_scanner import ProcessScanner
from detector.analyzer import ProcessAnalyzer
from detector.virus_checker import VirusTotalChecker
from alerts.alert_manager import AlertManager
from datetime import datetime
import json

app = Flask(__name__)

# Initialize components
scanner = ProcessScanner()
analyzer = ProcessAnalyzer()
vt_checker = VirusTotalChecker()
alert_manager = AlertManager()

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_system():
    """Scan system for suspicious processes"""
    try:
        # Step 1: Get all running processes
        processes = scanner.get_running_processes()
        
        # Step 2: Analyze processes for suspicious behavior
        suspicious = analyzer.analyze_processes(processes)
        
        # Step 3: Validate with VirusTotal
        results = []
        for proc in suspicious:
            vt_result = vt_checker.check_process(proc)
            proc['virus_total_result'] = vt_result
            results.append(proc)
            
            # Generate alert if threat detected
            if vt_result['is_malicious']:
                alert_manager.generate_alert(proc)
        
        return jsonify({
            'success': True,
            'total_processes': len(processes),
            'suspicious_count': len(suspicious),
            'results': results,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/alerts')
def get_alerts():
    """Get all alerts"""
    alerts = alert_manager.get_all_alerts()
    return render_template('alerts.html', alerts=alerts)

@app.route('/terminate-process', methods=['POST'])
def terminate_process():
    """Terminate a malicious process"""
    try:
        pid = request.json.get('pid')
        success = scanner.terminate_process(pid)
        
        if success:
            alert_manager.log_action(f"Process {pid} terminated successfully")
            return jsonify({'success': True, 'message': 'Process terminated'})
        else:
            return jsonify({'success': False, 'message': 'Failed to terminate process'})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
