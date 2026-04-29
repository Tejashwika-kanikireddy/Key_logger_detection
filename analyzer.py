class ProcessAnalyzer:
    """Analyzes processes for suspicious keylogger behavior"""
    
    def __init__(self):
        self.suspicious_behaviors = {
            'name_keywords': ['keylog', 'keycap', 'keystroke', 'logger', 'spy', 'monitor'],
            'suspicious_paths': ['temp', 'appdata', 'programdata'],
            'known_keyloggers': []
        }
        self.load_signatures()
    
    def load_signatures(self):
        """Load known keylogger signatures from file"""
        try:
            with open('signatures/keylogger_signatures.txt', 'r') as f:
                self.suspicious_behaviors['known_keyloggers'] = [
                    line.strip() for line in f.readlines() if line.strip()
                ]
        except FileNotFoundError:
            print("Signature file not found, using default detection only")
    
    def analyze_processes(self, processes):
        """Analyze list of processes and return suspicious ones"""
        suspicious_processes = []
        
        for proc in processes:
            risk_score = 0
            reasons = []
            
            if self.check_suspicious_name(proc['name']):
                risk_score += 30
                reasons.append("Suspicious process name")
            
            if proc['exe'] and self.check_suspicious_path(proc['exe']):
                risk_score += 25
                reasons.append("Running from suspicious directory")
            
            if proc['hash'] and self.check_known_signature(proc['hash']):
                risk_score += 50
                reasons.append("Matches known keylogger signature")
            
            if self.check_suspicious_cmdline(proc['cmdline']):
                risk_score += 20
                reasons.append("Suspicious command line arguments")
            
            # NEW: Check for keyboard hooks
            if self.check_keyboard_hooks(proc['name']):
                risk_score += 35
                reasons.append("Potential keyboard monitoring detected")
            
            if risk_score >= 30:
                proc['risk_score'] = risk_score
                proc['risk_level'] = self.get_risk_level(risk_score)
                proc['detection_reasons'] = reasons
                suspicious_processes.append(proc)
        
        return suspicious_processes
    
    def check_suspicious_name(self, name):
        """Check if process name contains suspicious keywords"""
        name_lower = name.lower()
        return any(keyword in name_lower for keyword in self.suspicious_behaviors['name_keywords'])
    
    def check_suspicious_path(self, path):
        """Check if executable is in suspicious directory"""
        path_lower = path.lower()
        return any(suspicious in path_lower for suspicious in self.suspicious_behaviors['suspicious_paths'])
    
    def check_known_signature(self, file_hash):
        """Check if file hash matches known keylogger"""
        return file_hash in self.suspicious_behaviors['known_keyloggers']
    
    def check_suspicious_cmdline(self, cmdline):
        """Check command line for suspicious patterns"""
        suspicious_patterns = ['hide', 'stealth', 'invisible', 'keylog', 'capture']
        cmdline_lower = cmdline.lower()
        return any(pattern in cmdline_lower for pattern in suspicious_patterns)
    
    def check_keyboard_hooks(self, process_name):
        """NEW: Check if process name suggests keyboard monitoring"""
        hook_keywords = ['hook', 'input', 'keyboard', 'keybd', 'winlogon']
        name_lower = process_name.lower()
        return any(keyword in name_lower for keyword in hook_keywords)
    
    def get_risk_level(self, score):
        """Determine risk level based on score"""
        if score >= 70:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 30:
            return "MEDIUM"
        else:
            return "LOW"
    
    def demonstrate_keylogger_behavior(self):
        """
        NEW: Shows what WOULD happen if a keylogger was detected
        This is a SIMULATION, not real keystroke capture
        """
        return {
            'simulated_threat': True,
            'type': 'Keystroke Capture Detected',
            'risk_level': 'CRITICAL',
            'description': 'Demonstration: If a process was monitoring keyboard input, it would trigger this alert'
        }
