import email
from email import policy
from email.parser import BytesParser

def extract_email_content(email_file):
    with open(email_file, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)
        
    subject = msg['subject']
    from_address = msg['from']
    body = msg.get_body(preferencelist=('plain')).get_content()
    
    return subject, from_address, body

import re

def extract_links(body):
    urls = re.findall(r'(https?://\S+)', body)
    return urls

def check_suspicious_links(urls):
    for url in urls:
        if is_untrusted_domain(url):  # You could implement or use an API for this
            return True
    return False

def is_untrusted_domain(url):
    # Dummy check for demonstration
    trusted_domains = ['example.com', 'paypal.com']
    return not any(domain in url for domain in trusted_domains)

from nltk import word_tokenize
from nltk.corpus import stopwords

def detect_phishing_phrases(body):
    phishing_keywords = ['urgent', 'verify', 'suspend', 'account', 'password']
    words = word_tokenize(body.lower())
    return any(word in phishing_keywords for word in words)

def scan_email_for_phishing(email_file):
    phishing_keywords = ["urgent", "verify", "account", "password"]
    found_keywords = []
    subject, from_address, body = extract_email_content(email_file)
    urls = extract_links(body)
    
    if check_suspicious_links(urls):
        return("Suspicious links found!")
        
    if detect_phishing_phrases(body):
        return("Urgent or phishing language detected!")
        