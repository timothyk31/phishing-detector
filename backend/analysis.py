import re

def check_spf(spf_header):
    """
    Check SPF (Sender Policy Framework) authentication results.
    
    Args:
        spf_header (str): The Received-SPF header value
        
    Returns:
        dict: Analysis result with risk score and details
    """
    # Default result structure
    result = {
        'check': 'SPF',
        'status': 'unknown',
        'risk_score': 0,  # 0-100, higher = more suspicious
        'is_suspicious': False,
        'details': {},
        'message': ''
    }
    
    # Handle missing or empty SPF header
    if not spf_header or spf_header.strip() == '':
        result['status'] = 'missing'
        result['risk_score'] = 70
        result['is_suspicious'] = True
        result['message'] = 'No SPF record found - sender cannot be verified'
        return result
    
    # Convert to lowercase for easier parsing
    spf_lower = spf_header.lower()
    
    # Extract SPF result (pass, fail, softfail, neutral, none, temperror, permerror)
    spf_result = None
    spf_results = ['pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror']
    
    for result_type in spf_results:
        if spf_lower.startswith(result_type):
            spf_result = result_type
            break
    
    if not spf_result:
        result['status'] = 'unknown'
        result['risk_score'] = 50
        result['is_suspicious'] = True
        result['message'] = 'Could not parse SPF result'
        return result
    
    # Extract additional details using regex
    # Extract domain
    domain_match = re.search(r'domain of ([^\s]+)', spf_header)
    sender_domain = domain_match.group(1) if domain_match else None
    
    # Extract client IP
    ip_match = re.search(r'client-ip=([0-9\.]+)', spf_header)
    client_ip = ip_match.group(1) if ip_match else None
    
    # Store details
    result['details'] = {
        'spf_result': spf_result,
        'sender_domain': sender_domain,
        'client_ip': client_ip,
        'raw_header': spf_header
    }
    
    # Analyze based on SPF result
    if spf_result == 'pass':
        result['status'] = 'pass'
        result['risk_score'] = 0
        result['is_suspicious'] = False
        result['message'] = f'SPF passed - Email authenticated from {sender_domain}'
    
    elif spf_result == 'fail':
        result['status'] = 'fail'
        result['risk_score'] = 95
        result['is_suspicious'] = True
        result['message'] = f'SPF FAILED - Sender IP {client_ip} is NOT authorized to send for {sender_domain}. High risk of spoofing!'
    
    elif spf_result == 'softfail':
        result['status'] = 'softfail'
        result['risk_score'] = 70
        result['is_suspicious'] = True
        result['message'] = f'SPF soft fail - Sender IP {client_ip} is questionable for {sender_domain}. Possible spoofing.'
    
    elif spf_result == 'neutral':
        result['status'] = 'neutral'
        result['risk_score'] = 40
        result['is_suspicious'] = True
        result['message'] = f'SPF neutral - Domain {sender_domain} makes no assertion about {client_ip}'
    
    elif spf_result == 'none':
        result['status'] = 'none'
        result['risk_score'] = 60
        result['is_suspicious'] = True
        result['message'] = f'No SPF record published for {sender_domain} - Cannot verify sender'
    
    elif spf_result in ['temperror', 'permerror']:
        result['status'] = spf_result
        result['risk_score'] = 50
        result['is_suspicious'] = True
        result['message'] = f'SPF check error for {sender_domain} - Verification incomplete'
    
    return result


def check_dkim(dkim_header):
    """
    Check DKIM (DomainKeys Identified Mail) authentication.
    
    Args:
        dkim_header (str): The DKIM-Signature header value
        
    Returns:
        dict: Analysis result with risk score and details
    """
    result = {
        'check': 'DKIM',
        'status': 'unknown',
        'risk_score': 0,
        'is_suspicious': False,
        'details': {},
        'message': ''
    }
    
    if not dkim_header or dkim_header.strip() == '':
        result['status'] = 'missing'
        result['risk_score'] = 60
        result['is_suspicious'] = True
        result['message'] = 'No DKIM signature found - Email integrity cannot be verified'
        return result
    
    # Extract domain from DKIM signature
    domain_match = re.search(r'd=([^;]+)', dkim_header)
    domain = domain_match.group(1) if domain_match else None
    
    result['details'] = {
        'domain': domain,
        'raw_header': dkim_header[:100] + '...'  # Truncate for readability
    }
    
    # DKIM presence is generally good, but we need Authentication-Results to know if it passed
    result['status'] = 'present'
    result['risk_score'] = 20
    result['is_suspicious'] = False
    result['message'] = f'DKIM signature present for {domain}'
    
    return result


def check_dmarc(auth_results_header):
    """
    Check DMARC (Domain-based Message Authentication) from Authentication-Results.
    
    Args:
        auth_results_header (str): The Authentication-Results header value
        
    Returns:
        dict: Analysis result with risk score and details
    """
    result = {
        'check': 'DMARC',
        'status': 'unknown',
        'risk_score': 0,
        'is_suspicious': False,
        'details': {},
        'message': ''
    }
    
    if not auth_results_header or auth_results_header.strip() == '':
        result['status'] = 'missing'
        result['risk_score'] = 50
        result['is_suspicious'] = True
        result['message'] = 'No authentication results found'
        return result
    
    auth_lower = auth_results_header.lower()
    
    # Check for DMARC result
    dmarc_pass = 'dmarc=pass' in auth_lower
    dmarc_fail = 'dmarc=fail' in auth_lower
    
    # Also check SPF and DKIM from this header
    spf_pass = 'spf=pass' in auth_lower
    dkim_pass = 'dkim=pass' in auth_lower
    
    result['details'] = {
        'dmarc_pass': dmarc_pass,
        'dmarc_fail': dmarc_fail,
        'spf_pass': spf_pass,
        'dkim_pass': dkim_pass,
        'raw_header': auth_results_header[:150] + '...'
    }
    
    if dmarc_pass:
        result['status'] = 'pass'
        result['risk_score'] = 0
        result['is_suspicious'] = False
        result['message'] = 'DMARC passed - Email authenticated successfully'
    elif dmarc_fail:
        result['status'] = 'fail'
        result['risk_score'] = 90
        result['is_suspicious'] = True
        result['message'] = 'DMARC FAILED - Email failed authentication checks. High risk!'
    else:
        result['status'] = 'not_found'
        result['risk_score'] = 40
        result['is_suspicious'] = True
        result['message'] = 'DMARC result not found in authentication headers'
    
    return result


def check_sender_mismatch(headers):
    """
    Check if From and Reply-To addresses match (common phishing tactic).
    
    Args:
        headers (dict): Email headers dictionary
        
    Returns:
        dict: Analysis result with risk score and details
    """
    result = {
        'check': 'Sender Mismatch',
        'status': 'unknown',
        'risk_score': 0,
        'is_suspicious': False,
        'details': {},
        'message': ''
    }
    
    from_addr = headers.get('from', '')
    reply_to = headers.get('reply_to', '')
    return_path = headers.get('return_path', '')
    
    # Extract email addresses using regex
    email_pattern = r'[\w\.-]+@[\w\.-]+\.\w+'
    
    from_email = re.findall(email_pattern, from_addr)
    reply_to_email = re.findall(email_pattern, reply_to)
    return_path_email = re.findall(email_pattern, return_path)
    
    from_email = from_email[0] if from_email else None
    reply_to_email = reply_to_email[0] if reply_to_email else None
    return_path_email = return_path_email[0] if return_path_email else None
    
    result['details'] = {
        'from_address': from_email,
        'reply_to_address': reply_to_email,
        'return_path': return_path_email
    }
    
    # Check for mismatches
    mismatches = []
    
    if reply_to_email and from_email and reply_to_email != from_email:
        # Extract domains
        from_domain = from_email.split('@')[1] if '@' in from_email else None
        reply_domain = reply_to_email.split('@')[1] if '@' in reply_to_email else None
        
        if from_domain != reply_domain:
            mismatches.append(f'From domain ({from_domain}) differs from Reply-To domain ({reply_domain})')
    
    if return_path_email and from_email and return_path_email != from_email:
        return_domain = return_path_email.split('@')[1] if '@' in return_path_email else None
        from_domain = from_email.split('@')[1] if '@' in from_email else None
        
        if return_domain != from_domain:
            mismatches.append(f'From domain ({from_domain}) differs from Return-Path domain ({return_domain})')
    
    if mismatches:
        result['status'] = 'mismatch'
        result['risk_score'] = 75
        result['is_suspicious'] = True
        result['message'] = 'Sender address mismatch detected: ' + '; '.join(mismatches)
        result['details']['mismatches'] = mismatches
    else:
        result['status'] = 'match'
        result['risk_score'] = 0
        result['is_suspicious'] = False
        result['message'] = 'Sender addresses are consistent'
    
    return result


def check_all_authentication(headers):
    """
    Run all authentication checks and return combined results.
    
    Args:
        headers (dict): Email headers dictionary
        
    Returns:
        dict: Combined authentication analysis
    """
    spf_result = check_spf(headers.get('spf', ''))
    dkim_result = check_dkim(headers.get('dkim', ''))
    dmarc_result = check_dmarc(headers.get('authentication_results', ''))
    mismatch_result = check_sender_mismatch(headers)
    
    # Calculate overall authentication score
    total_risk = (
        spf_result['risk_score'] * 0.35 +  # SPF is most important
        dmarc_result['risk_score'] * 0.30 +  # DMARC is very important
        dkim_result['risk_score'] * 0.20 +  # DKIM is important
        mismatch_result['risk_score'] * 0.15  # Mismatch is moderately important
    )
    
    # Determine overall status
    if total_risk >= 70:
        overall_status = 'high_risk'
        overall_message = 'Multiple authentication failures detected. HIGH RISK of phishing!'
    elif total_risk >= 40:
        overall_status = 'medium_risk'
        overall_message = 'Some authentication issues detected. Exercise caution.'
    else:
        overall_status = 'low_risk'
        overall_message = 'Email authentication checks passed.'
    
    return {
        'overall_risk_score': round(total_risk, 2),
        'overall_status': overall_status,
        'overall_message': overall_message,
        'checks': {
            'spf': spf_result,
            'dkim': dkim_result,
            'dmarc': dmarc_result,
            'sender_mismatch': mismatch_result
        }
    }
_all_ = [
    'check_spf',
    'check_dkim',
    'check_dmarc',
    'check_sender_mismatch',
    'check_all_authentication'
]