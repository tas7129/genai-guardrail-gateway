"""Registry of everything the scanner can detect.

Each entity type has:
  category     policy category (maps to a clause in the AI usage policy)
  label        human-readable name shown in the UI
  placeholder  text used in "[<PLACEHOLDER> REDACTED]" ("" = not redacted token-by-token)
  severity     default severity level: CRITICAL / HIGH / MEDIUM / LOW
               (the classifier can raise or lower it from context; overridable in
               policy/severity_policy.json -> entity_severity_overrides)
  scope        "token"    – a value that can be cut out of the prompt
               "document" – the content itself is sensitive (no single value to cut out);
                            governed by the category's document-level action (manager approval)
               "request"  – a property of the whole request (bulk records, unscannable file, harmful intent)
"""
from __future__ import annotations

from typing import Dict, NamedTuple

# ── Policy categories (A–L follow the censorship specification) ───────────
PERSONAL_DATA = "PERSONAL_DATA"                  # A
FINANCIAL_DATA = "FINANCIAL_DATA"                # B
CREDENTIALS = "CREDENTIALS"                      # C
MEDICAL_DATA = "MEDICAL_DATA"                    # D
CONFIDENTIAL_BUSINESS = "CONFIDENTIAL_BUSINESS"  # E
LEGAL_GOVERNMENT = "LEGAL_GOVERNMENT"            # F
LOCATION_DATA = "LOCATION_DATA"                  # G
PRIVATE_COMMUNICATIONS = "PRIVATE_COMMUNICATIONS"  # H
SENSITIVE_ATTRIBUTES = "SENSITIVE_ATTRIBUTES"    # I
CHILDREN_DATA = "CHILDREN_DATA"                  # J
SECURITY_TECHNICAL = "SECURITY_TECHNICAL"        # K
SOURCE_CODE = "SOURCE_CODE"                      # L (intellectual property; id kept for compatibility)
BULK_PERSONAL_DATA = "BULK_PERSONAL_DATA"
UNSCANNABLE_ATTACHMENT = "UNSCANNABLE_ATTACHMENT"
HARMFUL_CONTENT = "HARMFUL_CONTENT"
SAFETY_CHECK = "SAFETY_CHECK"  # the local safety classifier could not give a verdict

CATEGORY_LABELS = {
    PERSONAL_DATA: "Personally identifiable information",
    FINANCIAL_DATA: "Financial information",
    CREDENTIALS: "Credentials & secrets",
    MEDICAL_DATA: "Medical & health information",
    CONFIDENTIAL_BUSINESS: "Confidential business info",
    LEGAL_GOVERNMENT: "Legal & government information",
    LOCATION_DATA: "Location & tracking",
    PRIVATE_COMMUNICATIONS: "Private communications",
    SENSITIVE_ATTRIBUTES: "Sensitive personal attributes",
    CHILDREN_DATA: "Children's information",
    SECURITY_TECHNICAL: "Cybersecurity & technical secrets",
    SOURCE_CODE: "Intellectual property & source code",
    BULK_PERSONAL_DATA: "Bulk personal records",
    UNSCANNABLE_ATTACHMENT: "Unscannable attachment",
    HARMFUL_CONTENT: "Harmful or prohibited use",
    SAFETY_CHECK: "Content-safety check unavailable",
}
SPEC_GROUP = {
    PERSONAL_DATA: "A", FINANCIAL_DATA: "B", CREDENTIALS: "C", MEDICAL_DATA: "D", CONFIDENTIAL_BUSINESS: "E",
    LEGAL_GOVERNMENT: "F", LOCATION_DATA: "G", PRIVATE_COMMUNICATIONS: "H", SENSITIVE_ATTRIBUTES: "I",
    CHILDREN_DATA: "J", SECURITY_TECHNICAL: "K", SOURCE_CODE: "L",
}

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

# Higher wins when two detections overlap (after severity)
CATEGORY_PRIORITY = {
    HARMFUL_CONTENT: 9, SAFETY_CHECK: 9, CREDENTIALS: 8, FINANCIAL_DATA: 7, CHILDREN_DATA: 6, MEDICAL_DATA: 6,
    LEGAL_GOVERNMENT: 5, SECURITY_TECHNICAL: 5, LOCATION_DATA: 4, PERSONAL_DATA: 4,
    SENSITIVE_ATTRIBUTES: 3, PRIVATE_COMMUNICATIONS: 3, CONFIDENTIAL_BUSINESS: 2, SOURCE_CODE: 1,
}


class Entity(NamedTuple):
    category: str
    label: str
    placeholder: str
    severity: str
    scope: str = "token"


E = Entity
ENTITIES: Dict[str, Entity] = {
    # ── A · PII ───────────────────────────────────────────────────────────
    "AADHAAR": E(PERSONAL_DATA, "Aadhaar number", "AADHAAR NUMBER", "HIGH"),
    "PAN": E(PERSONAL_DATA, "PAN number", "PAN", "HIGH"),
    "PASSPORT": E(PERSONAL_DATA, "Passport number", "PASSPORT NUMBER", "HIGH"),
    "SSN": E(PERSONAL_DATA, "Social security number", "SSN", "HIGH"),
    "NATIONAL_ID": E(PERSONAL_DATA, "National ID number", "NATIONAL ID NUMBER", "HIGH"),
    "DRIVING_LICENCE": E(PERSONAL_DATA, "Driving licence number", "DRIVING LICENCE NUMBER", "HIGH"),
    "VOTER_ID": E(PERSONAL_DATA, "Voter ID (EPIC) number", "VOTER ID", "HIGH"),
    "BIOMETRIC": E(PERSONAL_DATA, "Biometric identifier", "BIOMETRIC DATA", "HIGH"),
    "PHONE": E(PERSONAL_DATA, "Phone number", "PHONE NUMBER", "MEDIUM"),
    "EMAIL": E(PERSONAL_DATA, "Email address", "EMAIL", "MEDIUM"),
    "ADDRESS": E(PERSONAL_DATA, "Residential / postal address", "ADDRESS", "MEDIUM"),
    "DATE_OF_BIRTH": E(PERSONAL_DATA, "Date of birth", "DATE OF BIRTH", "MEDIUM"),
    "IP_ADDRESS": E(PERSONAL_DATA, "IP address", "IP ADDRESS", "MEDIUM"),
    "PERSON_NAME": E(PERSONAL_DATA, "Person name (record field)", "NAME", "MEDIUM"),
    "EMPLOYEE_ID": E(PERSONAL_DATA, "Employee ID", "EMPLOYEE ID", "MEDIUM"),
    "STUDENT_RECORD": E(PERSONAL_DATA, "Student / school record", "SCHOOL RECORD", "MEDIUM"),
    # ── B · Financial ────────────────────────────────────────────────────
    "BANK_ACCOUNT": E(FINANCIAL_DATA, "Bank account number", "BANK ACCOUNT", "HIGH"),
    "CREDIT_CARD": E(FINANCIAL_DATA, "Credit / debit card number", "CARD NUMBER", "HIGH"),
    "CARD_CVV_PIN": E(FINANCIAL_DATA, "CVV / PIN", "CVV/PIN", "CRITICAL"),
    "UPI_ID": E(FINANCIAL_DATA, "UPI ID", "UPI ID", "MEDIUM"),
    "BANK_LOGIN": E(FINANCIAL_DATA, "Bank login credential", "BANK LOGIN", "CRITICAL"),
    "SALARY": E(FINANCIAL_DATA, "Salary / compensation", "SALARY", "MEDIUM"),
    "TAX_RECORD": E(FINANCIAL_DATA, "Tax record", "TAX RECORD", "MEDIUM"),
    "INSURANCE_POLICY": E(FINANCIAL_DATA, "Insurance policy number", "INSURANCE POLICY", "MEDIUM"),
    "TRANSACTION_ID": E(FINANCIAL_DATA, "Financial transaction record", "TRANSACTION ID", "MEDIUM"),
    "CRYPTO_PRIVATE_KEY": E(FINANCIAL_DATA, "Crypto wallet private key", "WALLET PRIVATE KEY", "CRITICAL"),
    "SEED_PHRASE": E(FINANCIAL_DATA, "Crypto wallet seed phrase", "WALLET SEED PHRASE", "CRITICAL"),
    # ── C · Credentials (all CRITICAL) ────────────────────────────────────
    "PASSWORD": E(CREDENTIALS, "Password", "PASSWORD", "CRITICAL"),
    "API_KEY": E(CREDENTIALS, "API key", "API KEY", "CRITICAL"),
    "AWS_ACCESS_KEY": E(CREDENTIALS, "AWS access key", "AWS ACCESS KEY", "CRITICAL"),
    "AWS_SECRET_KEY": E(CREDENTIALS, "AWS secret key", "AWS SECRET KEY", "CRITICAL"),
    "GITHUB_TOKEN": E(CREDENTIALS, "GitHub token", "GITHUB TOKEN", "CRITICAL"),
    "SLACK_TOKEN": E(CREDENTIALS, "Slack token", "SLACK TOKEN", "CRITICAL"),
    "ACCESS_TOKEN": E(CREDENTIALS, "Access / bearer token", "ACCESS TOKEN", "CRITICAL"),
    "REFRESH_TOKEN": E(CREDENTIALS, "Refresh token", "REFRESH TOKEN", "CRITICAL"),
    "OAUTH_SECRET": E(CREDENTIALS, "OAuth client secret", "OAUTH CLIENT SECRET", "CRITICAL"),
    "JWT": E(CREDENTIALS, "JSON Web Token", "JWT", "CRITICAL"),
    "PRIVATE_KEY": E(CREDENTIALS, "SSH / TLS private key", "PRIVATE KEY", "CRITICAL"),
    "ENCRYPTION_KEY": E(CREDENTIALS, "Encryption key", "ENCRYPTION KEY", "CRITICAL"),
    "CONNECTION_STRING": E(CREDENTIALS, "Database credentials", "DATABASE CREDENTIALS", "CRITICAL"),
    "SESSION_COOKIE": E(CREDENTIALS, "Session cookie", "SESSION COOKIE", "CRITICAL"),
    "OTP": E(CREDENTIALS, "One-time password", "OTP", "CRITICAL"),
    "RECOVERY_CODE": E(CREDENTIALS, "Recovery / backup codes", "RECOVERY CODES", "CRITICAL"),
    "CLOUD_CREDENTIAL": E(CREDENTIALS, "Cloud service credential", "CLOUD CREDENTIALS", "CRITICAL"),
    "GENERIC_SECRET": E(CREDENTIALS, "Secret / signing value", "SECRET", "CRITICAL"),
    # ── D · Medical (HIGH) ────────────────────────────────────────────────
    "MEDICAL_DIAGNOSIS": E(MEDICAL_DATA, "Medical diagnosis", "MEDICAL INFORMATION", "HIGH"),
    "MENTAL_HEALTH": E(MEDICAL_DATA, "Mental health information", "MEDICAL INFORMATION", "HIGH"),
    "REPRODUCTIVE_HEALTH": E(MEDICAL_DATA, "Reproductive health information", "MEDICAL INFORMATION", "HIGH"),
    "GENETIC_INFO": E(MEDICAL_DATA, "Genetic information", "MEDICAL INFORMATION", "HIGH"),
    "DISABILITY_INFO": E(MEDICAL_DATA, "Disability information", "MEDICAL INFORMATION", "HIGH"),
    "PRESCRIPTION": E(MEDICAL_DATA, "Prescription details", "MEDICAL INFORMATION", "HIGH"),
    "MEDICAL_RECORD": E(MEDICAL_DATA, "Medical record / test result", "MEDICAL INFORMATION", "HIGH"),
    # ── E · Confidential business (document-level) ───────────────────────
    "CONFIDENTIAL_MARKER": E(CONFIDENTIAL_BUSINESS, "Confidential marker", "", "HIGH", "document"),
    "BUSINESS_SENSITIVE_TERM": E(CONFIDENTIAL_BUSINESS, "Sensitive business topic", "", "HIGH", "document"),
    # ── F · Legal & government ───────────────────────────────────────────
    "CASE_NUMBER": E(LEGAL_GOVERNMENT, "Court / FIR case number", "CASE NUMBER", "HIGH"),
    "VISA_DETAILS": E(LEGAL_GOVERNMENT, "Immigration / visa details", "VISA DETAILS", "HIGH"),
    "LEGAL_MARKER": E(LEGAL_GOVERNMENT, "Privileged, sealed or classified material", "", "HIGH", "document"),
    # ── G · Location & tracking ──────────────────────────────────────────
    "GPS_COORDINATES": E(LOCATION_DATA, "GPS coordinates", "LOCATION", "HIGH"),
    "LIVE_LOCATION": E(LOCATION_DATA, "Live location link", "LOCATION", "HIGH"),
    "TRAVEL_BOOKING": E(LOCATION_DATA, "Travel booking reference", "BOOKING REFERENCE", "MEDIUM"),
    "VEHICLE_NUMBER": E(LOCATION_DATA, "Vehicle registration number", "VEHICLE NUMBER", "MEDIUM"),
    # ── H · Private communications ───────────────────────────────────────
    "CHAT_PARTICIPANT": E(PRIVATE_COMMUNICATIONS, "Chat participant", "CONTACT NAME", "MEDIUM"),
    "EMAIL_CORRESPONDENT": E(PRIVATE_COMMUNICATIONS, "Email sender / recipient", "CORRESPONDENT", "MEDIUM"),
    "CONTACT_ENTRY": E(PRIVATE_COMMUNICATIONS, "Personal contact entry", "CONTACT", "MEDIUM"),
    # ── I · Sensitive personal attributes ────────────────────────────────
    "RELIGION": E(SENSITIVE_ATTRIBUTES, "Religious belief", "RELIGION", "MEDIUM"),
    "CASTE": E(SENSITIVE_ATTRIBUTES, "Caste", "CASTE", "MEDIUM"),
    "POLITICAL_AFFILIATION": E(SENSITIVE_ATTRIBUTES, "Political affiliation", "POLITICAL AFFILIATION", "MEDIUM"),
    "ETHNICITY": E(SENSITIVE_ATTRIBUTES, "Race / ethnicity", "ETHNICITY", "MEDIUM"),
    "SEXUAL_ORIENTATION": E(SENSITIVE_ATTRIBUTES, "Sexual orientation", "SEXUAL ORIENTATION", "MEDIUM"),
    "GENDER_IDENTITY": E(SENSITIVE_ATTRIBUTES, "Gender identity", "GENDER IDENTITY", "MEDIUM"),
    "UNION_MEMBERSHIP": E(SENSITIVE_ATTRIBUTES, "Trade union membership", "UNION MEMBERSHIP", "MEDIUM"),
    # ── J · Children ─────────────────────────────────────────────────────
    "CHILD_NAME": E(CHILDREN_DATA, "Child's name", "CHILD NAME", "HIGH"),
    # ── K · Cybersecurity & technical ────────────────────────────────────
    "INTERNAL_HOST": E(SECURITY_TECHNICAL, "Internal hostname", "INTERNAL HOST", "HIGH"),
    "INTERNAL_IP": E(SECURITY_TECHNICAL, "Internal network address", "INTERNAL IP", "HIGH"),
    "SECURITY_MARKER": E(SECURITY_TECHNICAL, "Undisclosed vulnerability / security document", "", "HIGH", "document"),
    # ── L · Intellectual property ────────────────────────────────────────
    "SOURCE_CODE_BLOCK": E(SOURCE_CODE, "Proprietary source code", "", "HIGH", "document"),
    "IP_MARKER": E(SOURCE_CODE, "Unpublished research / patent / proprietary design", "", "HIGH", "document"),
    # ── Request-level ────────────────────────────────────────────────────
    "BULK_RECORDS": E(BULK_PERSONAL_DATA, "Bulk personal records", "", "HIGH", "request"),
    "ATTACHMENT_ERROR": E(UNSCANNABLE_ATTACHMENT, "Attachment could not be scanned", "", "CRITICAL", "request"),
    "UNSAFE_CONTENT": E(HARMFUL_CONTENT, "Unsafe content (local safety model)", "", "CRITICAL", "request"),
    "SAFETY_CHECK_FAILED": E(SAFETY_CHECK, "Safety classifier gave no verdict", "", "CRITICAL", "request"),
    "SAFETY_ADVISORY": E(HARMFUL_CONTENT, "Safety advisory (not blocking)", "", "LOW", "request"),
    "IFSC": E(FINANCIAL_DATA, "IFSC bank branch code (public)", "IFSC", "LOW"),
    "USERNAME": E(PERSONAL_DATA, "Login username", "USERNAME", "MEDIUM"),
    "VIOLENCE": E(HARMFUL_CONTENT, "Violence against people or property", "", "CRITICAL", "request"),
    "WEAPONS": E(HARMFUL_CONTENT, "Weapons or explosives", "", "CRITICAL", "request"),
    "ILLEGAL_DRUGS": E(HARMFUL_CONTENT, "Illegal drug production", "", "CRITICAL", "request"),
    "SELF_HARM": E(HARMFUL_CONTENT, "Self-harm", "", "CRITICAL", "request"),
    "ILLEGAL_ACTIVITY": E(HARMFUL_CONTENT, "Illegal or abusive activity", "", "CRITICAL", "request"),
}

# Identifiers that count towards the bulk-records threshold
PERSONAL_IDENTIFIER_TYPES = {
    "EMAIL", "PHONE", "AADHAAR", "PAN", "PASSPORT", "SSN", "DRIVING_LICENCE", "VOTER_ID", "CREDIT_CARD",
    "BANK_ACCOUNT", "PERSON_NAME", "ADDRESS", "DATE_OF_BIRTH", "SALARY", "UPI_ID", "EMPLOYEE_ID",
    "CHILD_NAME", "CHAT_PARTICIPANT", "CONTACT_ENTRY",
}

# Entity types that become "children's information" when the request is about a minor
CHILD_ELEVATED_TYPES = {
    "PERSON_NAME", "ADDRESS", "PHONE", "EMAIL", "DATE_OF_BIRTH", "STUDENT_RECORD", "GPS_COORDINATES",
    "LIVE_LOCATION", "CHAT_PARTICIPANT", "MEDICAL_DIAGNOSIS", "MENTAL_HEALTH", "DISABILITY_INFO",
    "PRESCRIPTION", "MEDICAL_RECORD", "AADHAAR", "PASSPORT", "IP_ADDRESS",
}
