import re
import email
import argparse
import logging
import dns.resolver
import sys
import requests
import json
import dmarc
from abc import ABC, abstractmethod

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ASCII Art
print("""
  ______            __        __
 /_  __/   ____ _ / /____   / /
  / /    / __ `/ / / ___/  / /
 / /    / /_/ / / / /__   / /
/_/     \__,_/ /_/\___/  /_/
        CodeByKalvin
""")

# External Keyword file.
KEYWORDS_FILE = "keywords.json"

class HeaderAnalyzer(ABC):
    """Abstract base class for header analysis"""
    def __init__(self):
        """Initialize the EmailHeaderAnalyzer."""
        self.headers = {}
        self.analysis = []
        self.score = 0
        self.keywords = self._load_keywords()
    @abstractmethod
    def analyze_email(self):
       """Analyzes the email headers for common phishing indicators."""
       pass

    @abstractmethod
    def load_email_data(self, email_data):
       """Loads the email from the raw data."""
       pass

    def _load_keywords(self):
       """Loads keywords from JSON file"""
       try:
           with open(KEYWORDS_FILE, 'r') as f:
             keywords = json.load(f)
             logging.info("Keywords loaded")
             return keywords
       except (FileNotFoundError, json.JSONDecodeError) as e:
            logging.error(f"Error loading keywords file: {e}. Using default keywords.")
            return {
                 "general": ["urgent", "important", "verify", "password", "bank", "account", "login", "invoice", "security"],
                "url":  [r"https?:\/\/(?:bit\.ly|tinyurl\.com)\/\w+"]
                }

    def parse_headers(self):
      """Parses and prints email headers"""
      logging.info("Parsing headers...")
      for key, value in self.headers.items():
        print(f"{key}: {value}")
      print("-----------------------")

    def _check_for_patterns(self, text, patterns):
      """Checks for multiple patterns in the text"""
      matched_patterns = []
      for pattern in patterns:
          if re.search(pattern, text, re.IGNORECASE):
             matched_patterns.append(pattern)
      return matched_patterns

    def _check_for_keywords(self):
        """Checks the email body for suspicious keywords."""
        try:
            subject = self.headers.get("Subject", "").lower()
            body = str(self.headers).lower()

            for category, keywords in self.keywords.items():
               for keyword in keywords:
                    if category == "general":
                        if keyword in subject or keyword in body:
                          self.analysis.append(f"Suspicious keyword '{keyword}' found in subject or body.")
                          self.score += 10
                          logging.info(f"Keyword {keyword} detected.")
                    elif category == "url":
                        for pattern in self._check_for_patterns(body,keywords):
                             self.analysis.append(f"Suspicious URL found '{pattern}'.")
                             self.score += 20
                             logging.info(f"Keyword url {pattern} detected.")

        except Exception as e:
           logging.error(f"Error checking for keywords: {e}")

    def _send_alert(self, message, score):
      """Prints the analysis results."""
      if not self.analysis:
           print("No suspicious activity detected.")
           return
      print("----------------------")
      print("Analysis Results:")
      for finding in self.analysis:
          print(f"- {finding}")
      print("-----------------------")
      print(f"Phishing risk score: {score}")
      if score > 40:
           print("This email is potentially dangerous, be careful!")
class EmailHeaderAnalyzer(HeaderAnalyzer):
    """Analyzes email headers to detect phishing attempts."""
    def __init__(self):
        """Initialize the EmailHeaderAnalyzer."""
        super().__init__()
    def load_email_data(self, email_data):
        """Loads the email from the raw data."""
        try:
          msg = email.message_from_string(email_data)
          self.headers = msg
          logging.info("Headers loaded successfully")
        except Exception as e:
          logging.error(f"Error loading email data: {e}")
    def _analyze_from_header(self):
        """Analyzes the 'From' header for spoofing."""
        try:
          from_header = self.headers.get("From", "")
          if not from_header:
            return #No from header
          match = re.search(r"<([^>]+)>", from_header)
          if not match:
              self.analysis.append(f"Suspicious 'From' address format: {from_header}")
              self.score += 10
              return
          from_email = match.group(1)
          domain = from_email.split("@")[-1]
          return_path = self.headers.get("Return-Path", "")
          if return_path and not return_path.endswith(domain) and not return_path.startswith(f"<{from_email}>"):
              self.analysis.append(f"Mismatch between 'From' ({from_email}) and 'Return-Path' ({return_path}). This might indicate spoofing.")
              self.score += 30
          logging.info(f"'From' analysis: from_email:{from_email}, domain:{domain}, return_path:{return_path}")
        except Exception as e:
           logging.error(f"Error analyzing from header: {e}")
    def _analyze_received_headers(self):
      """Analyzes the Received headers"""
      try:
        logging.info("Analyzing received headers...")
        received_headers = self.headers.get_all("Received")
        if not received_headers:
          return #No received headers
        for header in received_headers:
          match = re.search(r"from\s+([\w\d\.-]+)", header)
          if match:
              hostname = match.group(1)
              try:
                 dns.resolver.resolve(hostname, 'A')
                 logging.info(f"Hostname '{hostname}' resolved successfully.")
              except Exception as e:
                logging.warning(f"Hostname '{hostname}' could not be resolved: {e}")
                self.analysis.append(f"Suspicious 'Received' header: '{header}'. Hostname could not be resolved.")
                self.score += 15
        logging.info("Finished analyzing received headers.")
      except Exception as e:
        logging.error(f"Error analyzing received headers: {e}")
    def _analyze_reply_to_header(self):
       """Analyze reply to header."""
       try:
        reply_to = self.headers.get("Reply-To", "")
        if not reply_to:
            return
        from_header = self.headers.get("From","")
        if not from_header:
            return #No from header

        from_match = re.search(r"<([^>]+)>", from_header)
        if not from_match:
            return # Invalid from header
        from_email = from_match.group(1)

        if reply_to != from_email and not reply_to.endswith(from_email.split("@")[-1]) and reply_to != "":
            self.analysis.append(f"Suspicious 'Reply-To' header: '{reply_to}', not the same as From header. This is unusual and could indicate a phishing attempt.")
            self.score += 15

       except Exception as e:
            logging.error(f"Error analyzing Reply-To header: {e}")
    def _analyze_spf_dkim_dmarc(self):
      """Check SPF, DKIM, and DMARC records."""
      try:
         from_header = self.headers.get("From","")
         if not from_header:
            return #No from header
         match = re.search(r"<([^>]+)>", from_header)
         if not match:
            return #Invalid from header
         from_email = match.group(1)
         domain = from_email.split("@")[-1]
         try:
              dmarc_result = dmarc.query(domain)
              if not dmarc_result.get("valid"):
                  self.analysis.append(f"Domain '{domain}' has invalid or missing DMARC records.")
                  self.score += 30
              if not dmarc_result.get("spf_record"):
                  self.analysis.append(f"Domain '{domain}' has no SPF records.")
                  self.score += 20
              if not dmarc_result.get("dkim_record"):
                 self.analysis.append(f"Domain '{domain}' has no DKIM records.")
                 self.score += 20
              logging.info(f"DMARC check for {domain}: {dmarc_result}")
         except Exception as e:
            logging.warning(f"Error analyzing SPF/DKIM/DMARC records for domain {domain}: {e}")
            self.analysis.append(f"Error analyzing SPF/DKIM/DMARC records for domain {domain}. Could indicate that the domain is not configured correctly for email authentication")
            self.score += 20
      except Exception as e:
          logging.error(f"Error analyzing SPF/DKIM/DMARC records: {e}")

    def analyze_email(self):
       """Analyzes the email headers for common phishing indicators."""
       logging.info("Starting email analysis...")
       self._analyze_from_header()
       self._analyze_received_headers()
       self._analyze_reply_to_header()
       self._analyze_spf_dkim_dmarc()
       self._check_for_keywords()
       logging.info("Finished analyzing email.")
       self._send_alert(self.analysis, self.score)


def main():
    parser = argparse.ArgumentParser(description="Email Header Analyzer for phishing detection.")
    parser.add_argument("-f", "--file", type=str, help="Path to the email file")
    args = parser.parse_args()

    email_data = ""
    if args.file:
        try:
            with open(args.file, 'r') as f:
               email_data = f.read()
        except FileNotFoundError:
            logging.error(f"File not found: {args.file}")
            return
    else:
       if not sys.stdin.isatty(): # check if data is being piped to stdin
         email_data = sys.stdin.read()
       else:
          print("To use this script, pass an email file with '-f', or pipe the email data to standard input.")
          return

    if not email_data:
      print("No email data provided.")
      return

    analyzer = EmailHeaderAnalyzer()
    analyzer.load_email_data(email_data)
    analyzer.parse_headers()
    analyzer.analyze_email()


if __name__ == "__main__":
    main()
