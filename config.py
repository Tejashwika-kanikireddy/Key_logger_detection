import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Config:
    # Flask Configuration
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-here')
    DEBUG = os.getenv('DEBUG', 'True') == 'True'
    
    # VirusTotal API Configuration
    VT_API_KEY = os.getenv('VT_API_KEY', 'YOUR_VIRUSTOTAL_API_KEY')
    
    # Detection Configuration
    RISK_THRESHOLD = 30
    MAX_DETECTIONS_PER_SCAN = 50
    
    # Alert Configuration
    ENABLE_CONSOLE_ALERTS = True
    ENABLE_EMAIL_ALERTS = False
    
    # Logging Configuration
    LOG_DIRECTORY = 'logs'
    LOG_FILE = 'detection_logs.txt'
