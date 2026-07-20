from datetime import datetime
import json
import os

class AlertManager:
    """Manages real-time alerts and logging for detected threats"""
    
    def __init__(self):
        self.alerts = []
        self.log_file = 'logs/detection_logs.txt'
        self.ensure_log_directory()
    
    def ensure_log_directory(self):
        """Create logs directory if it doesn't exist"""
        os.makedirs('logs', exist_ok=True)
    
    def generate_alert(self, process_info):
        """Generate a real-time alert for detected threat"""
        alert = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'alert_type': 'KEYLOGGER_DETECTED',
            'severity': process_info.get('risk_level', 'UNKNOWN'),
            'process_name': process_info['name'],
            'process_id': process_info['pid'],
            'detection_reasons': process_info.get('detection_reasons', []),
            'virus_total': process_info.get('virus_total_result', {}),
            'status': 'ACTIVE'
        }
        
        self.alerts.append(alert)
        self.log_alert(alert)
        self.display_alert(alert)
        
        return alert
    
    def display_alert(self, alert):
        """Display alert in console"""
        print("\n" + "="*70)
        print(f"🚨 SECURITY ALERT - {alert['severity']} 🚨")
        print("="*70)
        print(f"Time: {alert['timestamp']}")
        print(f"Threat Type: {alert['alert_type']}")
        print(f"Process: {alert['process_name']} (PID: {alert['process_id']})")
        print(f"Detection Reasons:")
        for reason in alert['detection_reasons']:
            print(f"  - {reason}")
        
        vt_result = alert['virus_total']
        if vt_result.get('checked'):
            print(f"VirusTotal: {vt_result.get('message', 'N/A')}")
        
        print("="*70 + "\n")
    
    def log_alert(self, alert):
        """Log alert to file"""
        try:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(alert) + '\n')
        except Exception as e:
            print(f"Error logging alert: {e}")
    
    def log_action(self, action_message):
        """Log system actions"""
        log_entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'type': 'ACTION',
            'message': action_message
        }
        
        try:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            print(f"Error logging action: {e}")
    
    def get_all_alerts(self):
        """Retrieve all alerts from memory"""
        return self.alerts
    
    def get_recent_alerts(self, count=10):
        """Get most recent alerts"""
        return self.alerts[-count:] if len(self.alerts) > count else self.alerts
    
    def clear_alerts(self):
        """Clear all alerts from memory"""
        self.alerts = []
    
    def get_alert_statistics(self):
        """Get statistics about alerts"""
        total = len(self.alerts)
        
        severity_count = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }
        
        for alert in self.alerts:
            severity = alert.get('severity', 'UNKNOWN')
            if severity in severity_count:
                severity_count[severity] += 1
        
        return {
            'total_alerts': total,
            'severity_breakdown': severity_count,
            'active_threats': sum(1 for a in self.alerts if a['status'] == 'ACTIVE')
        }
