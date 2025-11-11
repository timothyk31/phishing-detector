from flask import Flask, request, jsonify
import email
from email import policy
from email.parser import BytesParser
import base64
import hashlib
from datetime import datetime
import json
from pathlib import Path

app = Flask(__name__)

def parse_eml_file(file_content):
    """
    Parse an .eml file and extract all relevant information
    """
    # Parse the email using BytesParser for better handling of attachments
    msg = BytesParser(policy=policy.default).parsebytes(file_content)
    
    # Extract headers
    headers = {
        'from': msg.get('From', ''),
        'to': msg.get('To', ''),
        'subject': msg.get('Subject', ''),
        'date': msg.get('Date', ''),
        'reply_to': msg.get('Reply-To', ''),
        'return_path': msg.get('Return-Path', ''),
        'message_id': msg.get('Message-ID', ''),
        'received': msg.get_all('Received', []),  # Multiple Received headers
        'spf': msg.get('Received-SPF', ''),
        'dkim': msg.get('DKIM-Signature', ''),
        'authentication_results': msg.get('Authentication-Results', ''),
    }
    
    # Extract body content
    body_text = ""
    body_html = ""
    
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get('Content-Disposition', ''))
            
            # Skip attachments for now
            if 'attachment' in content_disposition:
                continue
                
            if content_type == 'text/plain':
                try:
                    body_text += part.get_content()
                except:
                    pass
            elif content_type == 'text/html':
                try:
                    body_html += part.get_content()
                except:
                    pass
    else:
        # Not multipart - simple email
        content_type = msg.get_content_type()
        if content_type == 'text/plain':
            body_text = msg.get_content()
        elif content_type == 'text/html':
            body_html = msg.get_content()
    
    # Extract URLs from text and HTML
    import re
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    
    urls_in_text = re.findall(url_pattern, body_text)
    urls_in_html = re.findall(url_pattern, body_html)
    all_urls = list(set(urls_in_text + urls_in_html))  # Remove duplicates
    
    # Extract attachments
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = str(part.get('Content-Disposition', ''))
            
            if 'attachment' in content_disposition:
                filename = part.get_filename()
                if filename:
                    content = part.get_content()
                    
                    # Handle binary content
                    if isinstance(content, bytes):
                        file_bytes = content
                    else:
                        file_bytes = content.encode()
                    
                    # Calculate file hash
                    file_hash = hashlib.sha256(file_bytes).hexdigest()
                    
                    attachments.append({
                        'filename': filename,
                        'content_type': part.get_content_type(),
                        'size': len(file_bytes),
                        'hash_sha256': file_hash,
                        # Store base64 for potential further processing
                        'content_base64': base64.b64encode(file_bytes).decode('utf-8')
                    })
    
    # Return parsed data
    return {
        'headers': headers,
        'body': {
            'text': body_text,
            'html': body_html
        },
        'urls': all_urls,
        'attachments': attachments,
        'parsed_at': datetime.utcnow().isoformat()
    }


@app.route('/analyze-email', methods=['POST'])
def analyze_email():
    """
    Endpoint to upload and parse .eml files
    """
    # Check if file was uploaded
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    
    # Check if filename is empty
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Check file extension
    if not file.filename.endswith('.eml'):
        return jsonify({'error': 'File must be a .eml file'}), 400
    
    try:
        # Read file content
        file_content = file.read()
        
        # Parse the email
        parsed_data = parse_eml_file(file_content)
        
        # Write parsed data to a new local text file in the backend directory
        try:
            output_dir = Path(__file__).parent
            timestamp = datetime.utcnow().strftime('%Y%m%dT%H%M%S%f')
            # sanitize filename base
            base_name = file.filename.rsplit('.', 1)[0]
            out_filename = f"parsed_{base_name}_{timestamp}.txt"
            out_path = output_dir / out_filename
            with out_path.open('w', encoding='utf-8') as out_f:
                json.dump(parsed_data, out_f, ensure_ascii=False, indent=2)
            # include saved file path in response
            saved_file_path = str(out_path)
        except Exception as wf:
            # If writing fails, attach the error to the parsed data but do not stop response
            parsed_data['_write_error'] = str(wf)
            saved_file_path = None
        
        # Here you would add your phishing detection logic
        # For now, just return the parsed data
        
        resp = {
            'success': True,
            'data': parsed_data,
            'saved_file': saved_file_path
        }

        return jsonify(resp), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'}), 200


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)