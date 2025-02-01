import requests
import time


class VirusTotalAnalyzer:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = 'https://www.virustotal.com/api/v3'
        self.headers = {
            'x-apikey': self.api_key
        }

    def analyze_url(self, url):
        """
        Check URL reputation on VirusTotal
        """
        # URL analysis endpoint
        url_analysis_endpoint = f'{self.base_url}/urls'

        # First, submit URL for scanning
        payload = {'url': url}
        response = requests.post(url_analysis_endpoint, headers=self.headers, data=payload)

        if response.status_code != 200:
            return {'detected': False, 'error': 'Failed to submit URL'}

        # Get analysis ID
        analysis_id = response.json().get('id')

        # Wait and get results
        time.sleep(20)  # VirusTotal needs time to analyze

        analysis_results_endpoint = f'{self.base_url}/analyses/{analysis_id}'
        results_response = requests.get(analysis_results_endpoint, headers=self.headers)

        if results_response.status_code != 200:
            return {'detected': False, 'error': 'Failed to get URL analysis'}

        results = results_response.json()

        # Check if any vendor flags the URL as malicious
        malicious_count = results.get('data', {}).get('attributes', {}).get('stats', {}).get('malicious', 0)

        return {
            'detected': malicious_count > 0,
            'details': results
        }

    def analyze_ip(self, ip):
        """
        Check IP reputation on VirusTotal
        """
        # IP analysis endpoint
        ip_analysis_endpoint = f'{self.base_url}/ip_addresses/{ip}'

        response = requests.get(ip_analysis_endpoint, headers=self.headers)

        if response.status_code != 200:
            return {'detected': False, 'error': 'Failed to analyze IP'}

        results = response.json()

        # Check suspicious or malicious count
        suspicious_count = results.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get(
            'suspicious', 0)
        malicious_count = results.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious',
                                                                                                           0)

        return {
            'detected': suspicious_count > 0 or malicious_count > 0,
            'details': results
        }