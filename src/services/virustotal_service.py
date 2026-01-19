"""
VirusTotal service for scanning URLs and IP addresses.
"""
import requests
import time
from src.config import VIRUSTOTAL_API_KEY


def check_url_virustotal(url):
    """
    Check URL against VirusTotal API.
    
    Args:
        url (str): URL to check
        
    Returns:
        dict: Scan results with malicious, suspicious, and harmless counts
    """
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        
        # Submit URL for scanning
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url}
        )
        
        if response.status_code != 200:
            return {}
        
        analysis_id = response.json().get("data", {}).get("id", "")
        if not analysis_id:
            return {}
        
        # Wait for analysis to complete (with retries)
        for _ in range(5):
            time.sleep(2)
            report_response = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers
            )
            if report_response.status_code == 200:
                break
        
        # Extract statistics
        report = report_response.json()
        stats = report.get("data", {}).get("attributes", {}).get("stats", {})
        
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0)
        }
        
    except Exception as e:
        print(f"Error checking URL {url}: {e}")
        return {}


def check_ip_virustotal(ip):
    """
    Check IP address against VirusTotal API.
    
    Args:
        ip (str): IP address to check
        
    Returns:
        dict: Scan results with malicious, suspicious, and harmless counts
    """
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers=headers
        )
        
        if response.status_code != 200:
            return {}
        
        data = response.json().get("data", {})
        stats = data.get("attributes", {}).get("last_analysis_stats", {})
        
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0)
        }
        
    except Exception as e:
        print(f"Error checking IP {ip}: {e}")
        return {}
