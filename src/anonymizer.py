import hashlib
from faker import Faker
from typing import Dict, Any

fake = Faker()

class Anonymizer:
    """
    Consistent Pseudonymization & Masking Engine.
    Ensures that identical PII entities appearing multiple times across a document
    are consistently mapped to the exact same synthetic replacement.
    """

    def __init__(self, mode: str = "pseudonymize", seed: int = 42):
        self.mode = mode  # 'pseudonymize' or 'mask'
        self.seed = seed
        Faker.seed(seed)
        self.entity_map: Dict[str, str] = {}

    def reset(self):
        """Reset the internal mapping state."""
        self.entity_map.clear()

    def anonymize(self, original_text: str, pii_type: str) -> str:
        """
        Return the anonymized replacement for a given PII string and type.
        """
        clean_text = original_text.strip()
        key = f"{pii_type}::{clean_text.lower()}"

        if key in self.entity_map:
            return self.entity_map[key]

        if self.mode == "mask":
            replacement = f"[REDACTED {pii_type.upper()}]"
        else:
            replacement = self._generate_pseudonym(clean_text, pii_type)

        self.entity_map[key] = replacement
        return replacement

    def _generate_pseudonym(self, original_text: str, pii_type: str) -> str:
        """Generate realistic synthetic alternative using Faker based on PII type."""
        # Use deterministic hash to pick consistent fake data
        hash_val = int(hashlib.md5(original_text.encode('utf-8')).hexdigest(), 16)

        if pii_type == "PERSON":
            # Match capitalization style (ALL CAPS vs Title Case)
            fake_name = fake.name()
            if original_text.isupper():
                return fake_name.upper()
            return fake_name

        elif pii_type == "EMAIL":
            # If email contains person name or company name, generate clean fake email
            user_part = original_text.split("@")[0]
            domain = "example.com"
            clean_user = "".join([c for c in user_part if c.isalnum() or c in "._-"])
            return f"redacted.{clean_user}@{domain}"

        elif pii_type == "PHONE":
            # Preserve prefix if +91
            if original_text.startswith("+91") or original_text.startswith("91"):
                num_str = str(hash_val % 900000000 + 9000000000)
                return f"+91 {num_str[:5]} {num_str[5:]}"
            elif original_text.startswith("0"):
                area = str(original_text[:3])
                rest = str(hash_val % 90000000 + 10000000)
                return f"{area}-{rest}"
            else:
                return f"+1 ({hash_val % 800 + 200}) 555-{hash_val % 9000 + 1000}"

        elif pii_type == "COMPANY":
            fake_company = fake.company()
            if original_text.isupper():
                return fake_company.upper()
            return fake_company

        elif pii_type == "ADDRESS":
            fake_addr = f"{hash_val % 999 + 1} Innovation Way, Tech Park, Metro City - {hash_val % 899999 + 100000}, India"
            if original_text.isupper():
                return fake_addr.upper()
            return fake_addr

        elif pii_type in ("SSN", "CIN_PAN"):
            if "CIN" in pii_type or len(original_text) > 15:
                return "U12345MH2025PLC999999"
            elif len(original_text) == 10:
                return "ABCDE1234F"  # Fake Indian PAN format
            return f"{hash_val % 899 + 100}-{hash_val % 89 + 10}-{hash_val % 8999 + 1000}"

        elif pii_type == "CREDIT_CARD":
            return f"4111-XXXX-XXXX-{hash_val % 8999 + 1000}"

        elif pii_type == "DATE_OF_BIRTH":
            return "01/01/1990"

        elif pii_type == "IP_ADDRESS":
            return f"10.0.{hash_val % 250 + 1}.{hash_val % 250 + 1}"

        else:
            return f"[REDACTED_{pii_type}]"
