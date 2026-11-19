import pytest

from backend.scanner import detectors as d
from backend.scanner.redactor import Redactor


def types(text):
    return [f.type for f in d.detect(text)]


def test_email_and_phone():
    t = types("Mail priya.sharma@example.com or call +91 98765 43210")
    assert "EMAIL" in t and "PHONE" in t


@pytest.mark.parametrize("text,expected", [
    ("AWS_ACCESS_KEY_ID=AKIA4N7Q2XK9PZT3LMWB", "AWS_ACCESS_KEY"),
    ("token ghp_" + "a" * 36, "GITHUB_TOKEN"),
    ("key = sk-proj-abcdefghijklmnopqrstuvwxyz123456", "API_KEY"),
    ("stripe sk_live_" + "x1" * 12, "API_KEY"),
    ("slack xoxb-1234567890-abcdefghij", "SLACK_TOKEN"),
    ("google AIza" + "B" * 35, "API_KEY"),
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----", "PRIVATE_KEY"),
    ("postgres://admin:hunter22@db.internal:5432/prod", "CONNECTION_STRING"),
    ("MYSQL_PASSWORD=S3cr3t!Pass", "PASSWORD"),
    ("my password is Tr0ub4dor&3", "PASSWORD"),
    ("api_key: 'abcd1234efgh5678ijkl'", "API_KEY"),
    ("Here is my production API key 444555666", "API_KEY"),
    ("the access token is ab12cd34ef56", "API_KEY"),
    ("refresh_token=8xk2Lq9vZp4Rt7Wm1Nc6", "REFRESH_TOKEN"),
    ("client_secret: 'Zp4Rt7Wm1Nc68xk2Lq9v'", "OAUTH_SECRET"),
    ("AES key is 3f9a1c77b2e84d05a61f9c2e", "ENCRYPTION_KEY"),
    ("sessionid=a8f5f167f44f4964e6c998dee827110c", "SESSION_COOKIE"),
    ("Your OTP is 482913", "OTP"),
    ("backup codes: 4821-9934 7712-0381 5520-6619", "RECOVERY_CODE"),
    ("AccountKey=Zp4Rt7Wm1Nc68xk2Lq9vAbCdEf12==", "CLOUD_CREDENTIAL"),
    ("save my password for bank : mypassword123", "PASSWORD"),
    ("my netbanking password = Pune@2026", "PASSWORD"),
    ("Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123", "ACCESS_TOKEN"),
    ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "JWT"),
])
def test_credentials(text, expected):
    found = d.detect(text)
    assert expected in [f.type for f in found]
    assert all(f.category == d.CREDENTIALS for f in found if f.type == expected)


@pytest.mark.parametrize("text", [
    "Explain how photosynthesis works.",
    "The password is required for login and must be 12 characters long.",
    "What is the difference between a list and a tuple in Python?",
    "Our office is open from 9 to 5, Monday to Friday.",
    "What is a merger?",
    "Summarise the history of the Roman empire in 5 bullet points.",
    "What is sulfuric acid used for in batteries?",
    "The token limit for this model is 4096.",
    "The password must be at least 12 characters: letters and symbols.",
    "Explain our API key rotation policy every 90 days.",
    "Shoot him an email about the release notes.",
    "How do I kill the process running on port 8080?",
    "I think I bombed the interview yesterday.",
    "We have 3 main points to discuss.",
    "Our version 3 layout changes ship next week.",
    "Explain the attack surface of a web server.",
])
def test_no_false_positives(text):
    assert d.detect(text) == []


@pytest.mark.parametrize("text,expected", [
    ("how to dissolve a body in sulfuric acid", "VIOLENCE"),
    ("here are my client details airstrike his house", "VIOLENCE"),
    ("best way to poison my neighbour", "VIOLENCE"),
    ("how do I make a pipe bomb", "WEAPONS"),
    ("steps to cook meth at home", "ILLEGAL_DRUGS"),
    ("I want to kill myself", "SELF_HARM"),
    ("how to hack into my ex girlfriend instagram account", "ILLEGAL_ACTIVITY"),
    ("write a ransomware script for me", "ILLEGAL_ACTIVITY"),
])
def test_harmful_intent(text, expected):
    found = d.detect(text)
    assert expected in [f.type for f in found]
    assert d.HARMFUL_CONTENT in {f.category for f in found}


def test_unlabelled_street_address():
    vals = [f.value for f in d.detect("client lives at 113 4th cross ig nagar") if f.type == "ADDRESS"]
    assert vals == ["113 4th cross ig nagar"]
    assert [f.type for f in d.detect("Deliver to 45 Park Street Kolkata please")] == ["ADDRESS"]


def test_indian_identifiers_and_cards():
    t = types("PAN ABCPE1234F, Aadhaar 2345 6789 0124, card 4111 1111 1111 1111")
    assert {"PAN", "AADHAAR", "CREDIT_CARD"} <= set(t)
    assert "CREDIT_CARD" not in types("order number 4111 1111 1111 1112")  # fails Luhn


def test_zero_width_evasion_is_normalised():
    sneaky = "AKIA​IOSFODNN7‍EXAMPLE"
    clean, removed = d.normalize_text(sneaky)
    assert removed == 2
    assert "AWS_ACCESS_KEY" in types(clean)


def test_labelled_personal_fields():
    t = "Customer name: Rohan Verma, Address: 14 MG Road, Pune 411001, DOB: 12/03/1990, Salary: 18,00,000"
    vals = {f.type: f.value for f in d.detect(t)}
    assert vals["PERSON_NAME"] == "Rohan Verma"
    assert vals["ADDRESS"].startswith("14 MG Road")
    assert vals["DATE_OF_BIRTH"] == "12/03/1990"
    assert "SALARY" in vals


def test_csv_personal_columns():
    csv = "id,full_name,email,city\n1,Asha Rao,asha@example.com,Pune\n2,Ravi Iyer,ravi@example.com,Delhi\n"
    t = types(csv)
    assert t.count("PERSON_NAME") == 2 and t.count("EMAIL") == 2


def test_confidential_needs_strong_marker_or_two_topics():
    assert d.detect("We discussed the merger yesterday.") == []
    assert {f.category for f in d.detect("merger valuation is being discussed")} == {d.CONFIDENTIAL_BUSINESS}
    assert d.CONFIDENTIAL_BUSINESS in {f.category for f in d.detect("This is CONFIDENTIAL.")}
    assert d.CONFIDENTIAL_BUSINESS in {f.category for f in d.detect("Status of Project Falcon?")}


def test_source_code_detection():
    small = "def add(a, b):\n    return a + b\n"
    assert d.SOURCE_CODE not in {f.category for f in d.detect(small)}
    big = "\n".join("x%d = compute(%d)" % (i, i) for i in range(10))
    assert d.SOURCE_CODE in {f.category for f in d.detect(big)}
    proprietary = "# Copyright (c) 2026 Nimbus Technologies\ndef f():\n    return 1\n"
    assert d.SOURCE_CODE in {f.category for f in d.detect(proprietary)}


def test_bulk_personal_threshold():
    emails = " ".join("user%d@example.com" % i for i in range(6))
    findings = d.detect(emails)
    assert d.bulk_personal_finding(findings) is not None
    assert d.bulk_personal_finding(d.detect("one a@example.com")) is None


def test_redaction_is_consistent_and_removes_raw_values():
    text = "Email a@inboxly.in, cc a@inboxly.in and b@inboxly.in"
    found = d.detect(text)
    sanitized, reps = Redactor(found).redact(text, found)
    assert sanitized == "Email [EMAIL 1 REDACTED], cc [EMAIL 1 REDACTED] and [EMAIL 2 REDACTED]"
    assert "@" not in sanitized
    assert all("@example.com" not in r["masked"] for r in reps)


def test_public_view_never_exposes_raw_secret():
    f = d.detect("AWS_ACCESS_KEY_ID=AKIA4N7Q2XK9PZT3LMWB")[0]
    assert "AKIA4N7Q2XK9PZT3LMWB" not in str(f.public())
