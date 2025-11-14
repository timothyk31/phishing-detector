import os
import requests
from dotenv import load_dotenv
def checkSafeBrowsing(urls_to_check):
    ''' This function checks the URLs against Google's Safe Browsing API.
        It returns True if the URL is safe, False otherwise.
    '''

    current_dir = os.path.dirname(os.path.abspath(__file__))
    env_file = os.path.join(current_dir, ".env")
    if os.path.exists(env_file):
        load_dotenv(env_file)
        google_api_key = os.getenv("GOOGLE_API_KEY")
    else:
        raise ValueError("No .env file found in the current directory.")
    if not google_api_key:
        raise ValueError("Google API key not found in environment variables.")
        
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={google_api_key}"

    url_payloads = [{"url": url_to_check} for url_to_check in urls_to_check]
    payload = {
        "client": {
            "clientId": "477PhishingDetector",
            "clientVersion": "1.5.2"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": url_payloads
        }
    }
    
    response = requests.post(api_url, json=payload)
    if response.status_code != 200:
        raise Exception(f"Error checking URL: {response.status_code} - {response.text}")
    result = response.json()
    return result

_all__ = ['checkSafeBrowsing']