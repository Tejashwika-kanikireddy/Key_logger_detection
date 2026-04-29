import requests
import time
import os

class VirusTotalChecker:
    """Integrates with VirusTotal API to validate suspicious processes"""
    
    def __init__(self):
        self.api_key = os.getenv('VT_API_KEY', 'YOUR_API_KEY_HERE')
        self.base_url = 'https://www.virustotal.com/api/v3'
        self.headers = {'x-apikey': self.api_key}
    
    def check_process(self, process_info):
        """Check process hash against VirusTotal database"""
        
        if not process_info.get('hash'):
            return {
                'checked': False,
                'is_malicious': False,
                'detection_count': 0,
                'total_engines': 0,
                'message': 'No file hash available'
            }
        
        try:
            file_hash = process_info['hash']
            url = f"{self.base_url}/files/{file_hash}"
            
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 204:
                time.sleep(15)
                return self.check_process(process_info)
            
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                
                malicious_count = stats.get('malicious', 0)
                suspicious_count = stats.get('suspicious', 0)
                total_engines = sum(stats.values())
                
                is_malicious = (malicious_count + suspicious_count) > 5
                
                return {
                    'checked': True,
                    'is_malicious': is_malicious,
                    'detection_count': malicious_count + suspicious_count,
                    'total_engines': total_engines,
                    'message': f'{malicious_count + suspicious_count}/{total_engines} engines detected as malicious',
                    'permalink': f"https://www.virustotal.com/gui/file/{file_hash}"
                }
            
            elif response.status_code == 404:
                return {
                    'checked': True,
                    'is_malicious': False,
                    'detection_count': 0,
                    'total_engines': 0,
                    'message': 'File not found in VirusTotal database'
                }
            
            else:
                return {
                    'checked': False,
                    'is_malicious': False,
                    'detection_count': 0,
                    'total_engines': 0,
                    'message': f'API error: {response.status_code}'
                }
        
        except Exception as e:
            return {
                'checked': False,
                'is_malicious': False,
                'detection_count': 0,
                'total_engines': 0,
                'message': f'Error: {str(e)}'
            }
