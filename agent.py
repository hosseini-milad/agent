import sys
import os
import time
import json
import hashlib
import getpass
import logging
import platform
import uuid
import xml.etree.ElementTree as ET
from logging.handlers import RotatingFileHandler
from collections import deque
from datetime import datetime, timedelta, timezone

import psutil
import requests
import win32evtlog
import win32evtlogutil
import win32service
import win32serviceutil
import win32event
import servicemanager
from dotenv import load_dotenv

# ----------------- تنظیمات مسیرها -----------------
def get_base_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

BASE_DIR = get_base_dir()
ENV_PATH = os.path.join(BASE_DIR, '.env')

PROGRAM_DATA_DIR = os.path.join(os.environ.get('ProgramData', 'C:\\ProgramData'), 'SystemAgent')
os.makedirs(PROGRAM_DATA_DIR, exist_ok=True)

LAST_RECORD_FILE = os.path.join(PROGRAM_DATA_DIR, 'last_records.json')
LOG_FILE = os.path.join(PROGRAM_DATA_DIR, 'agent.log')

load_dotenv(ENV_PATH)

# ----------------- تنظیم لاگر فایل -----------------
logger = logging.getLogger('SystemAgentLogger')
logger.setLevel(logging.INFO)

handler = RotatingFileHandler(LOG_FILE, maxBytes=1024*1024, backupCount=3, encoding='utf-8')
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# ----------------- متغیرها و اولویت‌بندی لاگ‌ها -----------------
SERVER_URL = os.getenv('SERVER_URL', 'http://127.0.0.1:8080/logs')
ADMIN_HASH = os.getenv('ADMIN_PASSWORD_HASH', '')
API_TOKEN = os.getenv('API_TOKEN', '')
MAX_CACHE = 5
COLLECT_INTERVAL = 60
LOG_LOOKBACK_MINUTES = 1

# لیست سفید (Whitelist) برای رویدادهای مهم
PRIORITY_EVENT_IDS = {
    'Microsoft-Windows-Sysmon/Operational': {1, 3, 11, 13, 22}, # Process, Network, File, Reg, DNS
    'Security': {4624, 4625, 4672, 4688, 1102, 4720, 4726, 4732, 4648, 4673} 
}

pending_queue = deque() 

# ----------------- توابع کمکی -----------------
def check_password():
    if not ADMIN_HASH:
        print('Error: ADMIN_PASSWORD_HASH is not set in .env')
        return False
    pwd = getpass.getpass('Enter admin password: ')
    pwd_hash = hashlib.sha256(pwd.encode()).hexdigest()
    if pwd_hash == ADMIN_HASH:
        return True
    print('Error: Incorrect password.')
    return False

def load_last_records():
    if os.path.exists(LAST_RECORD_FILE):
        try:
            with open(LAST_RECORD_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_last_records(records):
    try:
        with open(LAST_RECORD_FILE, 'w') as f:
            json.dump(records, f)
    except Exception:
        pass

# ----------------- دریافت اطلاعات سخت‌افزاری -----------------
def get_static_system_info():
    try:
        mac = uuid.getnode()
        mac_str = ':'.join(('%012X' % mac)[i:i+2] for i in range(0, 12, 2))
    except Exception:
        mac_str = "Unknown"
        
    try:
        disk_total = round(psutil.disk_usage('C:\\').total / (1024**3), 2)
    except Exception:
        disk_total = 0.0

    return {
        "hostname": platform.node(),
        "os_name": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "cpu_cores_physical": psutil.cpu_count(logical=False),
        "cpu_cores_logical": psutil.cpu_count(logical=True),
        "total_ram_gb": round(psutil.virtual_memory().total / (1024**3), 2),
        "total_disk_c_gb": disk_total,
        "mac_address": mac_str
    }

# ----------------- جمع‌آوری لاگ‌ها با فیلتر -----------------
def get_recent_events(log_type, last_record_num):
    events = []
    try:
        query_flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
        query = win32evtlog.EvtQuery(log_type, query_flags, "*")
        
        while True:
            try:
                events_batch = win32evtlog.EvtNext(query, 10, -1, 0)
            except Exception as e:
                if getattr(e, 'winerror', None) == 259:
                    break
                raise e
                
            if not events_batch:
                break
                
            for event in events_batch:
                xml_content = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                root = ET.fromstring(xml_content)
                
                for elem in root.iter():
                    if '}' in elem.tag:
                        elem.tag = elem.tag.split('}', 1)[1]
                
                record_id_elem = root.find('.//EventRecordID')
                record_id = int(record_id_elem.text) if record_id_elem is not None else 0
                
                if record_id <= last_record_num:
                    return events
                
                time_elem = root.find('.//TimeCreated')
                if time_elem is not None and 'SystemTime' in time_elem.attrib:
                    time_created = time_elem.attrib['SystemTime']
                    event_time = datetime.fromisoformat(time_created.replace('Z', '+00:00'))
                else:
                    event_time = datetime.now(timezone.utc)
                
                now_utc = datetime.now(timezone.utc)
                if now_utc - event_time > timedelta(minutes=LOG_LOOKBACK_MINUTES):
                    return events
                
                # --- شروع فیلتر کردن ---
                event_id_elem = root.find('.//EventID')
                event_id = int(event_id_elem.text) if event_id_elem is not None else 0
                
                level_elem = root.find('.//Level')
                level = int(level_elem.text) if level_elem is not None else 0
                
                # فیلتر برای Application و System: فقط خطاها و هشدارها
                if log_type in ['Application', 'System']:
                    if level not in [1, 2, 3]: # 1=Critical, 2=Error, 3=Warning
                        continue
                # فیلتر برای Sysmon و Security: فقط ID های لیست سفید
                else:
                    allowed_ids = PRIORITY_EVENT_IDS.get(log_type, set())
                    if event_id not in allowed_ids:
                        continue
                # --- پایان فیلتر کردن ---
                
                provider_elem = root.find('.//Provider')
                source = provider_elem.attrib.get('Name', 'Unknown') if provider_elem is not None else 'Unknown'
                
                computer_elem = root.find('.//Computer')
                computer = computer_elem.text if computer_elem is not None else "Unknown"

                event_data = {}
                data_nodes = root.findall('.//EventData/Data')
                for node in data_nodes:
                    name = node.attrib.get('Name')
                    if name and node.text is not None:
                        event_data[name] = node.text
                
                events.append({
                    'log': log_type,
                    'record_number': record_id,
                    'time': event_time.isoformat(),
                    'source': source,
                    'event_id': event_id,
                    'type': level,
                    'computer': computer,
                    'event_data': event_data,
                    'message': 'See event_data for details' # تغییر برای زیبایی
                })
    except Exception as e:
        logger.error(f"Error reading event log {log_type} via EvtQuery: {e}")
    
    return events

def collect_logs():
    last = load_last_records()
    all_logs = []
    log_types = ['Application', 'System', 'Security', 'Microsoft-Windows-Sysmon/Operational']
    
    for log_type in log_types:
        last_num = last.get(log_type, 0)
        events = get_recent_events(log_type, last_num)
        if events:
            all_logs.extend(events)
            last[log_type] = max(e['record_number'] for e in events)
    save_last_records(last)
    return all_logs

# ----------------- ارسال به سرور -----------------
def send_batch(payload):
    try:
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {API_TOKEN}'
        }
        resp = requests.post(
            SERVER_URL,
            json=payload,
            timeout=10,
            headers=headers
        )
        if resp.status_code in (200, 201, 202, 204):
            logger.info(f"Successfully sent payload to {SERVER_URL}")
            return True
        else:
            logger.warning(f"Server responded with status {resp.status_code}")
            return False
    except Exception as e:
        logger.error(f"Network error while sending payload: {e}")
        return False

def flush_queue():
    while pending_queue:
        payload = pending_queue[0]
        if send_batch(payload):
            pending_queue.popleft()
        else:
            logger.warning(f"Failed to send. Keeping {len(pending_queue)} payload(s) in cache.")
            break

def enqueue_and_send(payload):
    pending_queue.append(payload)
    flush_queue()

# ----------------- کلاس اصلی سرویس -----------------
class SystemAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = 'SystemAgent'
    _svc_display_name_ = 'System Monitoring Agent'
    _svc_description_ = 'Collects logs and system metrics every minute and sends to server.'

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.stop_requested = False

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        logger.info("Service stop requested. Shutting down...")
        win32event.SetEvent(self.hWaitStop)
        self.stop_requested = True

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        logger.info("=== System Agent Service Started ===")
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)
        self.main_loop()

    def collect_metrics_interruptible(self, duration=60):
        net1 = psutil.net_io_counters()
        disk1 = psutil.disk_io_counters()
        mem = psutil.virtual_memory()
        
        cpu_samples = []
        start_time = time.time()
        
        while time.time() - start_time < duration:
            if self.stop_requested:
                break
            cpu_samples.append(psutil.cpu_percent(interval=1))
        
        net2 = psutil.net_io_counters()
        disk2 = psutil.disk_io_counters()

        elapsed = max(time.time() - start_time, 1)
        avg_cpu = sum(cpu_samples) / len(cpu_samples) if cpu_samples else 0

        return {
            'timestamp': datetime.now().isoformat(),
            'cpu_percent': round(avg_cpu, 2),
            'memory_percent': round(mem.percent, 2),
            'memory_used_mb': round(mem.used / (1024 * 1024), 2),
            'disk_read_bytes_per_sec': round((disk2.read_bytes - disk1.read_bytes) / elapsed, 2),
            'disk_write_bytes_per_sec': round((disk2.write_bytes - disk1.write_bytes) / elapsed, 2),
            'net_sent_bytes_per_sec': round((net2.bytes_sent - net1.bytes_sent) / elapsed, 2),
            'net_recv_bytes_per_sec': round((net2.bytes_recv - net1.bytes_recv) / elapsed, 2),
        }

    def main_loop(self):
        is_first_payload = True 

        while not self.stop_requested:
            try:
                if len(pending_queue) >= MAX_CACHE:
                    logger.warning(f"Cache full ({MAX_CACHE}). Pausing new collections to preserve oldest data.")
                    flush_queue() 
                    if len(pending_queue) >= MAX_CACHE:
                        win32event.WaitForSingleObject(self.hWaitStop, COLLECT_INTERVAL * 1000)
                        continue

                logger.info("Collecting logs and metrics...")
                logs = collect_logs()
                metrics = self.collect_metrics_interruptible(COLLECT_INTERVAL)

                if self.stop_requested:
                    break

                payload = {
                    'agent_id': os.getenv('COMPUTERNAME', 'unknown'),
                    'timestamp': datetime.now().isoformat(),
                    'metrics': metrics,
                    'logs': logs,
                }

                if is_first_payload:
                    logger.info("Service just started. Attaching static system info to payload.")
                    payload['system_info'] = get_static_system_info()
                    is_first_payload = False

                logger.info(f"Metrics gathered: CPU {metrics['cpu_percent']}%, RAM {metrics['memory_percent']}%. Filtered Logs gathered: {len(logs)}")
                
                enqueue_and_send(payload)

            except Exception as e:
                logger.error(f"Agent error in main loop: {e}", exc_info=True)

            win32event.WaitForSingleObject(self.hWaitStop, 1000)

# ----------------- اجرای برنامه -----------------
if __name__ == '__main__':
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(SystemAgentService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        command = sys.argv[1].lower()
        if command in ['stop', 'remove', 'disable']:
            if not check_password():
                sys.exit(1)
        
        win32serviceutil.HandleCommandLine(SystemAgentService)