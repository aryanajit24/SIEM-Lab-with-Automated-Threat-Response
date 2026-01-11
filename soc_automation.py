#!/usr/bin/env python3
import json
import logging
import requests
import hashlib
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('soc_automation.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class SeverityLevel(Enum):
    """Alert severity levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class IncidentStatus(Enum):
    """Incident status enumeration"""
    NEW = "new"
    IN_PROGRESS = "in_progress"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


class ResponseAction(Enum):
    """Automated response action types"""
    BLOCK_IP = "block_ip"
    ISOLATE_HOST = "isolate_host"
    DISABLE_ACCOUNT = "disable_account"
    QUARANTINE_FILE = "quarantine_file"
    RESET_PASSWORD = "reset_password"
    ALERT_ANALYST = "alert_analyst"
    CREATE_TICKET = "create_ticket"


@dataclass
class Alert:
    """Represents a security alert"""
    id: str
    timestamp: datetime
    rule_id: str
    rule_description: str
    severity: SeverityLevel
    source_ip: str
    destination_ip: str
    hostname: str
    username: Optional[str] = None
    process: Optional[str] = None
    file_hash: Optional[str] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)
    threat_intel: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'rule_id': self.rule_id,
            'rule_description': self.rule_description,
            'severity': self.severity.name,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'hostname': self.hostname,
            'username': self.username,
            'process': self.process,
            'file_hash': self.file_hash,
            'threat_intel': self.threat_intel
        }


@dataclass
class Case:
    """Represents a security case/incident"""
    case_id: str
    title: str
    description: str
    severity: SeverityLevel
    status: IncidentStatus
    created_at: datetime
    updated_at: datetime
    assigned_to: Optional[str] = None
    alerts: List[Alert] = field(default_factory=list)
    actions_taken: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert case to dictionary"""
        return {
            'case_id': self.case_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.name,
            'status': self.status.value,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'assigned_to': self.assigned_to,
            'alert_count': len(self.alerts),
            'actions_taken': self.actions_taken,
            'notes': self.notes
        }


class WazuhConnector:
    """Connector for Wazuh SIEM API integration"""
    
    def __init__(self, api_url: str, username: str, password: str, verify_ssl: bool = True):
        """
        Initialize Wazuh connector
        
        Args:
            api_url: Wazuh API URL (e.g., https://wazuh-manager:55000)
            username: API username
            password: API password
            verify_ssl: Whether to verify SSL certificates
        """
        self.api_url = api_url.rstrip('/')
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.token = None
        self.token_expiry = None
        logger.info(f"Initialized Wazuh connector for {self.api_url}")
    
    def authenticate(self) -> bool:
        """
        Authenticate with Wazuh API and obtain JWT token
        
        Returns:
            bool: True if authentication successful
        """
        try:
            url = f"{self.api_url}/security/user/authenticate"
            response = requests.post(
                url,
                auth=(self.username, self.password),
                verify=self.verify_ssl,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                self.token = data.get('data', {}).get('token')
                # Token typically expires in 900 seconds (15 minutes)
                self.token_expiry = datetime.now() + timedelta(seconds=900)
                logger.info("Successfully authenticated with Wazuh API")
                return True
            else:
                logger.error(f"Authentication failed: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            logger.error(f"Error authenticating with Wazuh: {str(e)}")
            return False
    
    def _ensure_authenticated(self) -> bool:
        """Ensure we have a valid token"""
        if not self.token or not self.token_expiry or datetime.now() >= self.token_expiry:
            return self.authenticate()
        return True
    
    def get_alerts(self, 
                   limit: int = 100, 
                   severity_min: int = 3,
                   time_range: int = 3600) -> List[Alert]:
        """
        Retrieve alerts from Wazuh
        
        Args:
            limit: Maximum number of alerts to retrieve
            severity_min: Minimum severity level
            time_range: Time range in seconds (default: last hour)
            
        Returns:
            List of Alert objects
        """
        if not self._ensure_authenticated():
            logger.error("Failed to authenticate with Wazuh")
            return []
        
        try:
            headers = {'Authorization': f'Bearer {self.token}'}
            params = {
                'limit': limit,
                'sort': '-timestamp',
                'q': f'rule.level>={severity_min}'
            }
            
            url = f"{self.api_url}/security/alerts"
            response = requests.get(
                url,
                headers=headers,
                params=params,
                verify=self.verify_ssl,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                alerts = []
                
                for alert_data in data.get('data', {}).get('affected_items', []):
                    alert = self._parse_alert(alert_data)
                    if alert:
                        alerts.append(alert)
                
                logger.info(f"Retrieved {len(alerts)} alerts from Wazuh")
                return alerts
            else:
                logger.error(f"Failed to retrieve alerts: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Error retrieving alerts: {str(e)}")
            return []
    
    def _parse_alert(self, alert_data: Dict[str, Any]) -> Optional[Alert]:
        """Parse Wazuh alert data into Alert object"""
        try:
            # Map Wazuh severity level to SeverityLevel enum
            level = alert_data.get('rule', {}).get('level', 0)
            if level >= 12:
                severity = SeverityLevel.CRITICAL
            elif level >= 7:
                severity = SeverityLevel.HIGH
            elif level >= 4:
                severity = SeverityLevel.MEDIUM
            else:
                severity = SeverityLevel.LOW
            
            alert = Alert(
                id=alert_data.get('id', ''),
                timestamp=datetime.fromisoformat(alert_data.get('timestamp', '').replace('Z', '+00:00')),
                rule_id=alert_data.get('rule', {}).get('id', ''),
                rule_description=alert_data.get('rule', {}).get('description', ''),
                severity=severity,
                source_ip=alert_data.get('data', {}).get('srcip', 'unknown'),
                destination_ip=alert_data.get('data', {}).get('dstip', 'unknown'),
                hostname=alert_data.get('agent', {}).get('name', 'unknown'),
                username=alert_data.get('data', {}).get('dstuser'),
                process=alert_data.get('data', {}).get('process_name'),
                file_hash=alert_data.get('data', {}).get('file_hash'),
                raw_data=alert_data
            )
            return alert
        except Exception as e:
            logger.error(f"Error parsing alert: {str(e)}")
            return None
    
    def get_agent_info(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific agent"""
        if not self._ensure_authenticated():
            return None
        
        try:
            headers = {'Authorization': f'Bearer {self.token}'}
            url = f"{self.api_url}/agents/{agent_id}"
            
            response = requests.get(
                url,
                headers=headers,
                verify=self.verify_ssl,
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json().get('data', {})
            return None
        except Exception as e:
            logger.error(f"Error getting agent info: {str(e)}")
            return None


class ThreatIntelligence:
    """Threat intelligence lookup and enrichment"""
    
    def __init__(self, virustotal_api_key: Optional[str] = None,
                 abuseipdb_api_key: Optional[str] = None,
                 otx_api_key: Optional[str] = None):
        """
        Initialize threat intelligence module
        
        Args:
            virustotal_api_key: VirusTotal API key
            abuseipdb_api_key: AbuseIPDB API key
            otx_api_key: AlienVault OTX API key
        """
        self.virustotal_api_key = virustotal_api_key
        self.abuseipdb_api_key = abuseipdb_api_key
        self.otx_api_key = otx_api_key
        self.cache = {}
        self.cache_ttl = 3600  # 1 hour cache
        logger.info("Initialized Threat Intelligence module")
    
    def enrich_alert(self, alert: Alert) -> Alert:
        """
        Enrich alert with threat intelligence data
        
        Args:
            alert: Alert object to enrich
            
        Returns:
            Enriched Alert object
        """
        logger.info(f"Enriching alert {alert.id}")
        
        # Check IP reputation
        if alert.source_ip and alert.source_ip != 'unknown':
            ip_intel = self.check_ip_reputation(alert.source_ip)
            alert.threat_intel['source_ip_reputation'] = ip_intel
        
        if alert.destination_ip and alert.destination_ip != 'unknown':
            ip_intel = self.check_ip_reputation(alert.destination_ip)
            alert.threat_intel['destination_ip_reputation'] = ip_intel
        
        # Check file hash
        if alert.file_hash:
            hash_intel = self.check_file_hash(alert.file_hash)
            alert.threat_intel['file_hash_reputation'] = hash_intel
        
        return alert
    
    def check_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """
        Check IP address reputation across multiple threat intel sources
        
        Args:
            ip_address: IP address to check
            
        Returns:
            Dictionary with reputation data
        """
        cache_key = f"ip_{ip_address}"
        
        # Check cache
        if cache_key in self.cache:
            cached_data, timestamp = self.cache[cache_key]
            if time.time() - timestamp < self.cache_ttl:
                return cached_data
        
        reputation_data = {
            'ip': ip_address,
            'is_malicious': False,
            'score': 0,
            'sources': []
        }
        
        # Check AbuseIPDB
        if self.abuseipdb_api_key:
            abuseipdb_data = self._check_abuseipdb(ip_address)
            if abuseipdb_data:
                reputation_data['sources'].append(abuseipdb_data)
                if abuseipdb_data.get('abuse_confidence_score', 0) > 50:
                    reputation_data['is_malicious'] = True
                    reputation_data['score'] += abuseipdb_data.get('abuse_confidence_score', 0)
        
        # Check VirusTotal
        if self.virustotal_api_key:
            vt_data = self._check_virustotal_ip(ip_address)
            if vt_data:
                reputation_data['sources'].append(vt_data)
                if vt_data.get('malicious_count', 0) > 2:
                    reputation_data['is_malicious'] = True
                    reputation_data['score'] += vt_data.get('malicious_count', 0) * 10
        
        # Cache the result
        self.cache[cache_key] = (reputation_data, time.time())
        
        return reputation_data
    
    def _check_abuseipdb(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Check IP against AbuseIPDB"""
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            headers = {
                'Accept': 'application/json',
                'Key': self.abuseipdb_api_key
            }
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': '90'
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                return {
                    'source': 'AbuseIPDB',
                    'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                    'total_reports': data.get('totalReports', 0),
                    'is_whitelisted': data.get('isWhitelisted', False)
                }
        except Exception as e:
            logger.error(f"Error checking AbuseIPDB: {str(e)}")
        return None
    
    def _check_virustotal_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Check IP against VirusTotal"""
        try:
            url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
            headers = {'x-apikey': self.virustotal_api_key}
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json().get('data', {}).get('attributes', {})
                stats = data.get('last_analysis_stats', {})
                return {
                    'source': 'VirusTotal',
                    'malicious_count': stats.get('malicious', 0),
                    'suspicious_count': stats.get('suspicious', 0),
                    'harmless_count': stats.get('harmless', 0),
                    'reputation': data.get('reputation', 0)
                }
        except Exception as e:
            logger.error(f"Error checking VirusTotal: {str(e)}")
        return None
    
    def check_file_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Check file hash reputation
        
        Args:
            file_hash: File hash (MD5, SHA1, or SHA256)
            
        Returns:
            Dictionary with hash reputation data
        """
        cache_key = f"hash_{file_hash}"
        
        # Check cache
        if cache_key in self.cache:
            cached_data, timestamp = self.cache[cache_key]
            if time.time() - timestamp < self.cache_ttl:
                return cached_data
        
        reputation_data = {
            'hash': file_hash,
            'is_malicious': False,
            'detections': 0,
            'total_scanners': 0
        }
        
        if self.virustotal_api_key:
            try:
                url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
                headers = {'x-apikey': self.virustotal_api_key}
                
                response = requests.get(url, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    data = response.json().get('data', {}).get('attributes', {})
                    stats = data.get('last_analysis_stats', {})
                    
                    reputation_data['detections'] = stats.get('malicious', 0)
                    reputation_data['total_scanners'] = sum(stats.values())
                    reputation_data['is_malicious'] = stats.get('malicious', 0) > 5
                    
            except Exception as e:
                logger.error(f"Error checking file hash: {str(e)}")
        
        # Cache the result
        self.cache[cache_key] = (reputation_data, time.time())
        
        return reputation_data


class IncidentResponse:
    """Automated incident response actions"""
    
    def __init__(self, firewall_api: Optional[str] = None,
                 edr_api: Optional[str] = None,
                 ad_api: Optional[str] = None):
        """
        Initialize incident response module
        
        Args:
            firewall_api: Firewall API endpoint
            edr_api: EDR/Endpoint protection API endpoint
            ad_api: Active Directory API endpoint
        """
        self.firewall_api = firewall_api
        self.edr_api = edr_api
        self.ad_api = ad_api
        self.action_history = []
        logger.info("Initialized Incident Response module")
    
    def execute_response(self, alert: Alert, actions: List[ResponseAction]) -> List[Dict[str, Any]]:
        """
        Execute automated response actions
        
        Args:
            alert: Alert triggering the response
            actions: List of response actions to execute
            
        Returns:
            List of action results
        """
        logger.info(f"Executing {len(actions)} response actions for alert {alert.id}")
        results = []
        
        for action in actions:
            try:
                if action == ResponseAction.BLOCK_IP:
                    result = self.block_ip_address(alert.source_ip)
                elif action == ResponseAction.ISOLATE_HOST:
                    result = self.isolate_host(alert.hostname)
                elif action == ResponseAction.DISABLE_ACCOUNT:
                    result = self.disable_user_account(alert.username)
                elif action == ResponseAction.QUARANTINE_FILE:
                    result = self.quarantine_file(alert.hostname, alert.file_hash)
                elif action == ResponseAction.RESET_PASSWORD:
                    result = self.reset_user_password(alert.username)
                elif action == ResponseAction.ALERT_ANALYST:
                    result = self.alert_analyst(alert)
                elif action == ResponseAction.CREATE_TICKET:
                    result = self.create_ticket(alert)
                else:
                    result = {'success': False, 'message': f'Unknown action: {action}'}
                
                result['action'] = action.value
                result['timestamp'] = datetime.now().isoformat()
                results.append(result)
                self.action_history.append(result)
                
            except Exception as e:
                logger.error(f"Error executing action {action}: {str(e)}")
                results.append({
                    'action': action.value,
                    'success': False,
                    'message': str(e),
                    'timestamp': datetime.now().isoformat()
                })
        
        return results
    
    def block_ip_address(self, ip_address: str) -> Dict[str, Any]:
        """
        Block IP address at firewall
        
        Args:
            ip_address: IP address to block
            
        Returns:
            Action result dictionary
        """
        logger.info(f"Blocking IP address: {ip_address}")
        
        if not self.firewall_api:
            logger.warning("Firewall API not configured - simulating block")
            return {
                'success': True,
                'message': f'Simulated: IP {ip_address} blocked at firewall',
                'ip_address': ip_address
            }
        
        try:
            # Implement actual firewall API call here
            # Example for generic REST API:
            # response = requests.post(
            #     f"{self.firewall_api}/block",
            #     json={'ip': ip_address, 'duration': 3600},
            #     timeout=10
            # )
            
            return {
                'success': True,
                'message': f'IP {ip_address} blocked at firewall',
                'ip_address': ip_address
            }
        except Exception as e:
            logger.error(f"Error blocking IP: {str(e)}")
            return {
                'success': False,
                'message': f'Failed to block IP: {str(e)}',
                'ip_address': ip_address
            }
    
    def isolate_host(self, hostname: str) -> Dict[str, Any]:
        """
        Isolate host from network
        
        Args:
            hostname: Hostname to isolate
            
        Returns:
            Action result dictionary
        """
        logger.info(f"Isolating host: {hostname}")
        
        if not self.edr_api:
            logger.warning("EDR API not configured - simulating isolation")
            return {
                'success': True,
                'message': f'Simulated: Host {hostname} isolated from network',
                'hostname': hostname
            }
        
        try:
            # Implement actual EDR API call here
            return {
                'success': True,
                'message': f'Host {hostname} isolated from network',
                'hostname': hostname
            }
        except Exception as e:
            logger.error(f"Error isolating host: {str(e)}")
            return {
                'success': False,
                'message': f'Failed to isolate host: {str(e)}',
                'hostname': hostname
            }
    
    def disable_user_account(self, username: Optional[str]) -> Dict[str, Any]:
        """
        Disable user account
        
        Args:
            username: Username to disable
            
        Returns:
            Action result dictionary
        """
        if not username:
            return {
                'success': False,
                'message': 'No username provided'
            }
        
        logger.info(f"Disabling user account: {username}")
        
        if not self.ad_api:
            logger.warning("AD API not configured - simulating disable")
            return {
                'success': True,
                'message': f'Simulated: User account {username} disabled',
                'username': username
            }
        
        try:
            # Implement actual AD API call here
            return {
                'success': True,
                'message': f'User account {username} disabled',
                'username': username
            }
        except Exception as e:
            logger.error(f"Error disabling account: {str(e)}")
            return {
                'success': False,
                'message': f'Failed to disable account: {str(e)}',
                'username': username
            }
    
    def quarantine_file(self, hostname: str, file_hash: Optional[str]) -> Dict[str, Any]:
        """
        Quarantine suspicious file
        
        Args:
            hostname: Host where file is located
            file_hash: Hash of file to quarantine
            
        Returns:
            Action result dictionary
        """
        if not file_hash:
            return {
                'success': False,
                'message': 'No file hash provided'
            }
        
        logger.info(f"Quarantining file {file_hash} on {hostname}")
        
        return {
            'success': True,
            'message': f'Simulated: File {file_hash} quarantined on {hostname}',
            'hostname': hostname,
            'file_hash': file_hash
        }
    
    def reset_user_password(self, username: Optional[str]) -> Dict[str, Any]:
        """
        Force password reset for user
        
        Args:
            username: Username to reset password
            
        Returns:
            Action result dictionary
        """
        if not username:
            return {
                'success': False,
                'message': 'No username provided'
            }
        
        logger.info(f"Forcing password reset for: {username}")
        
        return {
            'success': True,
            'message': f'Simulated: Password reset forced for {username}',
            'username': username
        }
    
    def alert_analyst(self, alert: Alert) -> Dict[str, Any]:
        """
        Send alert notification to security analyst
        
        Args:
            alert: Alert to notify about
            
        Returns:
            Action result dictionary
        """
        logger.info(f"Alerting analyst about alert {alert.id}")
        
        # This would typically integrate with email, Slack, PagerDuty, etc.
        return {
            'success': True,
            'message': f'Analyst notified about alert {alert.id}'
        }
    
    def create_ticket(self, alert: Alert) -> Dict[str, Any]:
        """
        Create incident ticket in ticketing system
        
        Args:
            alert: Alert to create ticket for
            
        Returns:
            Action result dictionary
        """
        logger.info(f"Creating ticket for alert {alert.id}")
        
        # This would typically integrate with Jira, ServiceNow, etc.
        ticket_id = f"INC-{int(time.time())}"
        
        return {
            'success': True,
            'message': f'Ticket {ticket_id} created for alert {alert.id}',
            'ticket_id': ticket_id
        }


class CaseManagement:
    """Security case and incident management"""
    
    def __init__(self, storage_backend: str = 'memory'):
        """
        Initialize case management module
        
        Args:
            storage_backend: Storage backend type ('memory', 'file', 'database')
        """
        self.cases = {}
        self.storage_backend = storage_backend
        logger.info(f"Initialized Case Management module with {storage_backend} backend")
    
    def create_case(self, title: str, description: str, 
                   severity: SeverityLevel, alerts: List[Alert]) -> Case:
        """
        Create new security case
        
        Args:
            title: Case title
            description: Case description
            severity: Case severity
            alerts: List of alerts associated with case
            
        Returns:
            Created Case object
        """
        case_id = f"CASE-{int(time.time())}-{len(self.cases)}"
        
        case = Case(
            case_id=case_id,
            title=title,
            description=description,
            severity=severity,
            status=IncidentStatus.NEW,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            alerts=alerts
        )
        
        self.cases[case_id] = case
        logger.info(f"Created case {case_id}: {title}")
        
        return case
    
    def update_case_status(self, case_id: str, status: IncidentStatus) -> bool:
        """
        Update case status
        
        Args:
            case_id: Case ID to update
            status: New status
            
        Returns:
            bool: True if successful
        """
        if case_id not in self.cases:
            logger.error(f"Case {case_id} not found")
            return False
        
        self.cases[case_id].status = status
        self.cases[case_id].updated_at = datetime.now()
        logger.info(f"Updated case {case_id} status to {status.value}")
        
        return True
    
    def add_case_note(self, case_id: str, note: str) -> bool:
        """
        Add note to case
        
        Args:
            case_id: Case ID
            note: Note text
            
        Returns:
            bool: True if successful
        """
        if case_id not in self.cases:
            logger.error(f"Case {case_id} not found")
            return False
        
        timestamp = datetime.now().isoformat()
        self.cases[case_id].notes.append(f"[{timestamp}] {note}")
        self.cases[case_id].updated_at = datetime.now()
        logger.info(f"Added note to case {case_id}")
        
        return True
    
    def add_case_action(self, case_id: str, action: str) -> bool:
        """
        Record action taken on case
        
        Args:
            case_id: Case ID
            action: Action description
            
        Returns:
            bool: True if successful
        """
        if case_id not in self.cases:
            logger.error(f"Case {case_id} not found")
            return False
        
        timestamp = datetime.now().isoformat()
        self.cases[case_id].actions_taken.append(f"[{timestamp}] {action}")
        self.cases[case_id].updated_at = datetime.now()
        logger.info(f"Recorded action for case {case_id}")
        
        return True
    
    def assign_case(self, case_id: str, analyst: str) -> bool:
        """
        Assign case to analyst
        
        Args:
            case_id: Case ID
            analyst: Analyst name/ID
            
        Returns:
            bool: True if successful
        """
        if case_id not in self.cases:
            logger.error(f"Case {case_id} not found")
            return False
        
        self.cases[case_id].assigned_to = analyst
        self.cases[case_id].updated_at = datetime.now()
        logger.info(f"Assigned case {case_id} to {analyst}")
        
        return True
    
    def get_case(self, case_id: str) -> Optional[Case]:
        """
        Retrieve case by ID
        
        Args:
            case_id: Case ID
            
        Returns:
            Case object or None
        """
        return self.cases.get(case_id)
    
    def get_open_cases(self) -> List[Case]:
        """
        Get all open cases
        
        Returns:
            List of open Case objects
        """
        return [
            case for case in self.cases.values()
            if case.status not in [IncidentStatus.RESOLVED, IncidentStatus.CLOSED]
        ]
    
    def get_cases_by_severity(self, severity: SeverityLevel) -> List[Case]:
        """
        Get cases by severity level
        
        Args:
            severity: Severity level to filter by
            
        Returns:
            List of Case objects
        """
        return [
            case for case in self.cases.values()
            if case.severity == severity
        ]
    
    def export_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        """
        Export case data
        
        Args:
            case_id: Case ID to export
            
        Returns:
            Dictionary with case data or None
        """
        case = self.get_case(case_id)
        if not case:
            return None
        
        return case.to_dict()


class SOCAutomation:
    """Main SOC Automation orchestrator"""
    
    def __init__(self, 
                 wazuh_connector: WazuhConnector,
                 threat_intel: ThreatIntelligence,
                 incident_response: IncidentResponse,
                 case_management: CaseManagement):
        """
        Initialize SOC Automation engine
        
        Args:
            wazuh_connector: Configured WazuhConnector instance
            threat_intel: Configured ThreatIntelligence instance
            incident_response: Configured IncidentResponse instance
            case_management: Configured CaseManagement instance
        """
        self.wazuh = wazuh_connector
        self.threat_intel = threat_intel
        self.incident_response = incident_response
        self.case_mgmt = case_management
        self.playbooks = self._initialize_playbooks()
        logger.info("Initialized SOC Automation Engine")
    
    def _initialize_playbooks(self) -> Dict[str, Dict[str, Any]]:
        """
        Initialize automated response playbooks
        
        Returns:
            Dictionary of playbooks
        """
        return {
            'malicious_ip': {
                'name': 'Malicious IP Detection',
                'trigger': lambda alert: alert.threat_intel.get('source_ip_reputation', {}).get('is_malicious', False),
                'actions': [ResponseAction.BLOCK_IP, ResponseAction.ALERT_ANALYST],
                'auto_case': True
            },
            'malware_detection': {
                'name': 'Malware Detection',
                'trigger': lambda alert: alert.file_hash and alert.threat_intel.get('file_hash_reputation', {}).get('is_malicious', False),
                'actions': [ResponseAction.ISOLATE_HOST, ResponseAction.QUARANTINE_FILE, ResponseAction.ALERT_ANALYST],
                'auto_case': True
            },
            'brute_force': {
                'name': 'Brute Force Attack',
                'trigger': lambda alert: 'brute' in alert.rule_description.lower() or 'authentication' in alert.rule_description.lower(),
                'actions': [ResponseAction.BLOCK_IP, ResponseAction.ALERT_ANALYST],
                'auto_case': True
            },
            'privilege_escalation': {
                'name': 'Privilege Escalation',
                'trigger': lambda alert: 'privilege' in alert.rule_description.lower() or 'escalation' in alert.rule_description.lower(),
                'actions': [ResponseAction.ISOLATE_HOST, ResponseAction.DISABLE_ACCOUNT, ResponseAction.ALERT_ANALYST, ResponseAction.CREATE_TICKET],
                'auto_case': True
            },
            'data_exfiltration': {
                'name': 'Data Exfiltration',
                'trigger': lambda alert: 'exfiltration' in alert.rule_description.lower() or alert.severity == SeverityLevel.CRITICAL,
                'actions': [ResponseAction.ISOLATE_HOST, ResponseAction.BLOCK_IP, ResponseAction.ALERT_ANALYST, ResponseAction.CREATE_TICKET],
                'auto_case': True
            }
        }
    
    def process_alerts(self, limit: int = 100) -> Dict[str, Any]:
        """
        Main alert processing workflow
        
        Args:
            limit: Maximum number of alerts to process
            
        Returns:
            Processing summary dictionary
        """
        logger.info("=" * 80)
        logger.info("Starting SOC Automation Alert Processing")
        logger.info("=" * 80)
        
        summary = {
            'start_time': datetime.now().isoformat(),
            'alerts_processed': 0,
            'alerts_enriched': 0,
            'playbooks_triggered': 0,
            'cases_created': 0,
            'actions_executed': 0,
            'errors': []
        }
        
        try:
            # Fetch alerts from Wazuh
            alerts = self.wazuh.get_alerts(limit=limit, severity_min=3)
            summary['alerts_processed'] = len(alerts)
            logger.info(f"Retrieved {len(alerts)} alerts from Wazuh")
            
            for alert in alerts:
                try:
                    # Enrich alert with threat intelligence
                    enriched_alert = self.threat_intel.enrich_alert(alert)
                    summary['alerts_enriched'] += 1
                    
                    # Check playbooks
                    triggered_playbook = self._check_playbooks(enriched_alert)
                    
                    if triggered_playbook:
                        summary['playbooks_triggered'] += 1
                        logger.info(f"Playbook '{triggered_playbook['name']}' triggered for alert {alert.id}")
                        
                        # Execute automated response
                        actions = triggered_playbook['actions']
                        results = self.incident_response.execute_response(enriched_alert, actions)
                        summary['actions_executed'] += len(results)
                        
                        # Create case if configured
                        if triggered_playbook.get('auto_case', False):
                            case = self._create_case_from_alert(enriched_alert, triggered_playbook['name'])
                            summary['cases_created'] += 1
                            
                            # Record actions in case
                            for result in results:
                                self.case_mgmt.add_case_action(
                                    case.case_id,
                                    f"{result['action']}: {result['message']}"
                                )
                    
                except Exception as e:
                    error_msg = f"Error processing alert {alert.id}: {str(e)}"
                    logger.error(error_msg)
                    summary['errors'].append(error_msg)
            
        except Exception as e:
            error_msg = f"Critical error in alert processing: {str(e)}"
            logger.error(error_msg)
            summary['errors'].append(error_msg)
        
        summary['end_time'] = datetime.now().isoformat()
        
        logger.info("=" * 80)
        logger.info("SOC Automation Processing Summary:")
        logger.info(f"  Alerts Processed: {summary['alerts_processed']}")
        logger.info(f"  Alerts Enriched: {summary['alerts_enriched']}")
        logger.info(f"  Playbooks Triggered: {summary['playbooks_triggered']}")
        logger.info(f"  Cases Created: {summary['cases_created']}")
        logger.info(f"  Actions Executed: {summary['actions_executed']}")
        logger.info(f"  Errors: {len(summary['errors'])}")
        logger.info("=" * 80)
        
        return summary
    
    def _check_playbooks(self, alert: Alert) -> Optional[Dict[str, Any]]:
        """
        Check if alert triggers any playbook
        
        Args:
            alert: Alert to check
            
        Returns:
            Triggered playbook or None
        """
        for playbook_id, playbook in self.playbooks.items():
            try:
                if playbook['trigger'](alert):
                    return playbook
            except Exception as e:
                logger.error(f"Error evaluating playbook {playbook_id}: {str(e)}")
        
        return None
    
    def _create_case_from_alert(self, alert: Alert, playbook_name: str) -> Case:
        """
        Create case from alert
        
        Args:
            alert: Alert to create case from
            playbook_name: Name of triggered playbook
            
        Returns:
            Created Case object
        """
        title = f"{playbook_name} - {alert.rule_description}"
        description = f"""
Automated case created by SOC Automation Engine

Alert ID: {alert.id}
Rule: {alert.rule_id} - {alert.rule_description}
Severity: {alert.severity.name}
Source IP: {alert.source_ip}
Destination IP: {alert.destination_ip}
Hostname: {alert.hostname}
Username: {alert.username}
Timestamp: {alert.timestamp.isoformat()}

Threat Intelligence:
{json.dumps(alert.threat_intel, indent=2)}
        """.strip()
        
        case = self.case_mgmt.create_case(
            title=title,
            description=description,
            severity=alert.severity,
            alerts=[alert]
        )
        
        # Auto-assign based on severity
        if alert.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
            self.case_mgmt.update_case_status(case.case_id, IncidentStatus.INVESTIGATING)
        
        return case
    
    def add_custom_playbook(self, playbook_id: str, playbook_config: Dict[str, Any]) -> bool:
        """
        Add custom playbook
        
        Args:
            playbook_id: Unique playbook identifier
            playbook_config: Playbook configuration
            
        Returns:
            bool: True if successful
        """
        if playbook_id in self.playbooks:
            logger.warning(f"Playbook {playbook_id} already exists, overwriting")
        
        self.playbooks[playbook_id] = playbook_config
        logger.info(f"Added custom playbook: {playbook_id}")
        
        return True
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get SOC automation statistics
        
        Returns:
            Statistics dictionary
        """
        open_cases = self.case_mgmt.get_open_cases()
        critical_cases = self.case_mgmt.get_cases_by_severity(SeverityLevel.CRITICAL)
        
        return {
            'total_cases': len(self.case_mgmt.cases),
            'open_cases': len(open_cases),
            'critical_cases': len(critical_cases),
            'total_actions': len(self.incident_response.action_history),
            'active_playbooks': len(self.playbooks),
            'threat_intel_cache_size': len(self.threat_intel.cache)
        }


def main():
    """Example usage of SOC Automation Engine"""
    
    # Initialize components
    wazuh = WazuhConnector(
        api_url="https://wazuh-manager:55000",
        username="wazuh-admin",
        password="your-password"
    )
    
    threat_intel = ThreatIntelligence(
        virustotal_api_key="your-vt-api-key",
        abuseipdb_api_key="your-abuseipdb-key"
    )
    
    incident_response = IncidentResponse(
        firewall_api="https://firewall-api.local",
        edr_api="https://edr-api.local",
        ad_api="https://ad-api.local"
    )
    
    case_mgmt = CaseManagement(storage_backend='memory')
    
    # Initialize SOC Automation
    soc = SOCAutomation(
        wazuh_connector=wazuh,
        threat_intel=threat_intel,
        incident_response=incident_response,
        case_management=case_mgmt
    )
    
    # Process alerts
    summary = soc.process_alerts(limit=50)
    
    # Display statistics
    stats = soc.get_statistics()
    print("\n" + "=" * 80)
    print("SOC AUTOMATION STATISTICS")
    print("=" * 80)
    print(f"Total Cases: {stats['total_cases']}")
    print(f"Open Cases: {stats['open_cases']}")
    print(f"Critical Cases: {stats['critical_cases']}")
    print(f"Total Actions Executed: {stats['total_actions']}")
    print(f"Active Playbooks: {stats['active_playbooks']}")
    print("=" * 80)
    
    # Display open cases
    print("\nOPEN CASES:")
    print("-" * 80)
    for case in case_mgmt.get_open_cases():
        print(f"[{case.severity.name}] {case.case_id}: {case.title}")
        print(f"  Status: {case.status.value} | Created: {case.created_at}")
        print(f"  Actions: {len(case.actions_taken)} | Alerts: {len(case.alerts)}")
        print("-" * 80)


if __name__ == "__main__":
    main()
