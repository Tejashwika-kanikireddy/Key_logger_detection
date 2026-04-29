import psutil
import hashlib
import os

class ProcessScanner:
    """Scans and manages running processes on the system"""
    
    def __init__(self):
        self.suspicious_keywords = [
            'keylog', 'keycap', 'keystroke', 'keysniff',
            'logger', 'monitor', 'capture', 'spy', 'stealth'
        ]
    
    def get_running_processes(self):
        """Get list of all running processes with details"""
        processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time']):
            try:
                process_info = {
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'exe': proc.info['exe'],
                    'cmdline': ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else '',
                    'create_time': proc.info['create_time']
                }
                
                if proc.info['exe'] and os.path.exists(proc.info['exe']):
                    process_info['hash'] = self.calculate_file_hash(proc.info['exe'])
                else:
                    process_info['hash'] = None
                
                # NEW: Add network activity check
                process_info['network_activity'] = self.check_network_activity(proc.info['pid'])
                
                processes.append(process_info)
            
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        return processes
    
    def calculate_file_hash(self, file_path):
        """Calculate SHA256 hash of file"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return None
    
    def terminate_process(self, pid):
        """Terminate a process by PID"""
        try:
            process = psutil.Process(pid)
            process.terminate()
            process.wait(timeout=3)
            return True
        except Exception as e:
            print(f"Error terminating process {pid}: {e}")
            return False
    
    def is_suspicious_name(self, process_name):
        """Check if process name contains suspicious keywords"""
        process_name_lower = process_name.lower()
        for keyword in self.suspicious_keywords:
            if keyword in process_name_lower:
                return True
        return False
    
    def detect_keyboard_hooks(self):
        """NEW: Detects if processes are using Windows keyboard hooks"""
        suspicious = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                # Check if process name suggests keyboard monitoring
                name_lower = proc.info['name'].lower()
                if any(keyword in name_lower for keyword in ['hook', 'input', 'keyboard', 'keybd']):
                    suspicious.append({
                        'name': proc.info['name'],
                        'pid': proc.info['pid'],
                        'alert': 'Process may be monitoring keyboard input!'
                    })
            except:
                pass
        return suspicious
    
    def check_network_activity(self, pid):
        """NEW: Checks if a process is sending data over network"""
        try:
            connections = psutil.net_connections()
            for conn in connections:
                if conn.pid == pid and conn.raddr:
                    return {
                        'has_network': True,
                        'remote_address': str(conn.raddr),
                        'warning': 'Process is sending data!'
                    }
        except:
            pass
        return {'has_network': False}
    
    def get_advanced_process_info(self):
        """NEW: Get processes with advanced monitoring features"""
        processes = self.get_running_processes()
        keyboard_hooks = self.detect_keyboard_hooks()
        
        # Add keyboard hook information to processes
        for proc in processes:
            proc['keyboard_hook'] = any(
                hook['pid'] == proc['pid'] for hook in keyboard_hooks
            )
        
        return processes
