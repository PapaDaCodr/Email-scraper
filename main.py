import imaplib
import email
import socket
from email.header import decode_header
import re

# Replace with your email details
EMAIL = ""
PASSWORD = ""
IMAP_SERVER = "imap.gmail.com"
IMAP_PORT = 993

# List of common personal email domains to exclude
personal_email_domains = [
    "gmail.com", "yahoo.com", "aol.com", "outlook.com", "icloud.com", "hotmail.com"
]
def connect_to_mail_server():
    try:
        print("Connecting to the email server...")
        mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
        print("Connected to the email server.")
        mail.login(EMAIL, PASSWORD)
        mail.select("inbox")
        return mail
    except imaplib.IMAP4.error as e:
        print(f"IMAP error: {e}")
        return None

def extract_email_details(msg):
    subject = decode_header(msg["Subject"])[0][0]
    if isinstance(subject, bytes):
        subject = subject.decode()

    from_ = msg.get("From")
    to = msg.get("To")
    date = msg.get("Date")

    sender_name, sender_email = email.utils.parseaddr(from_)
    sender_domain = sender_email.split('@')[-1]

    return {
        "Subject": subject,
        "From": from_,
        "To": to,
        "Date": date,
        "Sender Name": sender_name,
        "Sender Email": sender_email,
        "Sender Domain": sender_domain
    }

# Regular expression for subject validation
subject_regex = re.compile(r'\b(receipt|order confirmation|invoice|payment|bill|summary)\b', re.IGNORECASE)

# Function to check if the email body contains specific patterns
def contains_receipt_keywords(msg):
    keywords = ["total", "amount charged", "payment received", "order summary", "invoice", "receipt", "confirmation"]
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ["text/plain", "text/html"]:
                try:
                    body = part.get_payload(decode=True).decode()
                    if any(keyword in body.lower() for keyword in keywords):
                        return True
                except Exception as e:
                    print(f"Error decoding part: {e}")
    else:
        try:
            body = msg.get_payload(decode=True).decode()
            if any(keyword in body.lower() for keyword in keywords):
                return True
        except Exception as e:
            print(f"Error decoding body: {e}")
    return False

def is_corporate_domain(sender_domain):
    return sender_domain.lower() not in personal_email_domains

def fetch_and_process_emails(mail):
    emails = []
    status, messages = mail.search(None, '(SINCE "01-Jun-2022")')
    if status != "OK":
        print("No messages found!")
        return emails

    message_ids = messages[0].split()
    print(f"Number of messages found since June 2022: {len(message_ids)}")
    message_ids = message_ids[:50]  # Limit to 50 messages

    for num in message_ids:
        try:
            status, msg_data = mail.fetch(num, "(RFC822)")
            if status != "OK":
                print(f"Error fetching email {num}")
                continue

            msg = email.message_from_bytes(msg_data[0][1])
            email_details = extract_email_details(msg)

            if (subject_regex.search(email_details["Subject"]) and
                    is_corporate_domain(email_details["Sender Domain"]) and
                    contains_receipt_keywords(msg)):
                emails.append(email_details)
            else:
                print(f"Email from {email_details['Sender Email']} did not match criteria.")
        except imaplib.IMAP4.error as e:
            print(f"IMAP error while fetching email {num}: {e}")
            continue

    return emails

def main():
    mail = connect_to_mail_server()
    if mail:
        emails = fetch_and_process_emails(mail)
        mail.logout()

        if emails:
            print("Filtered emails:")
            for email in emails:
                print(f"Subject: {email['Subject']}")
                print(f"From: {email['From']}")
                print(f"To: {email['To']}")
                print(f"Date: {email['Date']}\n")
        else:
            print("No emails matched the criteria.")

if __name__ == "__main__":
    main()
