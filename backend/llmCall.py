import os
from dotenv import load_dotenv
from google import genai

def call_llm(parsed_email_data):
    """
    Call Gemini API with the filled prompt template for email phishing analysis.
    
    Args:
        parsed_email_data (dict): The parsed email data from parse_eml_file
        
    Returns:
        dict: LLM analysis result containing risk assessment
    """
    load_dotenv()
    gemini_api_key = os.getenv("GEMINI_API_KEY")
    if not gemini_api_key:
        raise ValueError("Gemini API key not found in environment variables.")
    
    # Read the prompt template
    current_dir = os.path.dirname(os.path.abspath(__file__))
    prompt_file = os.path.join(current_dir, "llmprompt.txt")
    
    with open(prompt_file, "r") as f:
        prompt_template = f.read()
    
    # Extract data from parsed email
    headers = parsed_email_data.get('headers', {})
    body = parsed_email_data.get('body', {})
    urls = parsed_email_data.get('urls', [])
    attachments = parsed_email_data.get('attachments', [])
    auth_result = parsed_email_data.get('authentication_result', {})
    safebrowsing = parsed_email_data.get('safebrowsing', {})
    
    # Extract authentication results
    spf_check = auth_result.get('checks', {}).get('spf', {})
    dkim_check = auth_result.get('checks', {}).get('dkim', {})
    dmarc_check = auth_result.get('checks', {}).get('dmarc', {})
    
    spf_result = f"{spf_check.get('status', 'unknown')} - {spf_check.get('message', 'No SPF data')}"
    dkim_result = f"{dkim_check.get('status', 'unknown')} - {dkim_check.get('message', 'No DKIM data')}"
    dmarc_result = f"{dmarc_check.get('status', 'unknown')} - {dmarc_check.get('message', 'No DMARC data')}"
    
    # Format URLs and domains
    urls_list = "\n".join([f"- {url}" for url in urls]) if urls else "No URLs found"
    domains_list = "\n".join([f"- {url.split('/')[2]}" for url in urls if len(url.split('/')) > 2]) if urls else "No domains found"
    
    # Format attachments
    if attachments:
        attachments_info = "\n".join([
            f"- Filename: {att.get('filename')}, Type: {att.get('content_type')}, Size: {att.get('size')} bytes, SHA256: {att.get('hash_sha256')}"
            for att in attachments
        ])
    else:
        attachments_info = "No attachments"
    
    # Format Safe Browsing results
    if safebrowsing and safebrowsing.get('matches'):
        google_safe_browsing_results = "THREATS DETECTED:\n"
        for match in safebrowsing['matches']:
            google_safe_browsing_results += f"- URL: {match.get('threat', {}).get('url', 'N/A')}\n"
            google_safe_browsing_results += f"  Threat Type: {match.get('threatType', 'N/A')}\n"
            google_safe_browsing_results += f"  Platform: {match.get('platformType', 'N/A')}\n"
    else:
        google_safe_browsing_results = "No threats detected by Google Safe Browsing"
    
    # Placeholders for incomplete API integrations
    virustotal_results = "[PLACEHOLDER] VirusTotal analysis pending - API integration not yet complete"
    urlscan_results = "[PLACEHOLDER] urlscan.io analysis pending - API integration not yet complete"
    abuseipdb_results = "[PLACEHOLDER] AbuseIPDB analysis pending - API integration not yet complete"
    
    # Fill the prompt template
    filled_prompt = prompt_template.format(
        spf_result=spf_result,
        dkim_result=dkim_result,
        dmarc_result=dmarc_result,
        email_body=body.get('text', body.get('html', 'No body content'))[:5000],  # Limit body length
        subject_line=headers.get('subject', 'No subject'),
        sender_address=headers.get('from', 'Unknown sender'),
        reply_to_address=headers.get('reply_to', 'No reply-to address'),
        urls_list=urls_list,
        domains_list=domains_list,
        attachments_info=attachments_info,
        google_safe_browsing_results=google_safe_browsing_results,
        virustotal_results=virustotal_results,
        urlscan_results=urlscan_results,
        abuseipdb_results=abuseipdb_results
    )
    
    # Write filled prompt to file for debugging/logging
    filled_prompt_file = os.path.join(current_dir, "llmprompt_filled.txt")
    with open(filled_prompt_file, "w") as f:
        f.write(filled_prompt)
    
    try:
        # Initialize Gemini client with API key
        client = genai.Client(api_key=gemini_api_key)
        
        # Call Gemini API
        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=filled_prompt
        )
        
        # Extract the response text
        result_text = response.text
        
        return {
            'success': True,
            'analysis': result_text,
            'model': 'gemini-2.0-flash-exp',
            'prompt_file': filled_prompt_file
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'analysis': 'Error: Failed to get LLM analysis'
        }