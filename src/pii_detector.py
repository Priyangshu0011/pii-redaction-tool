import re
import spacy
from typing import List, Dict, Any, Tuple

# Load spaCy English model with only NER enabled for max speed and min memory
try:
    nlp = spacy.load("en_core_web_sm", disable=["parser", "lemmatizer", "attribute_ruler", "tagger"])
except Exception:
    import spacy.cli
    spacy.cli.download("en_core_web_sm")
    nlp = spacy.load("en_core_web_sm", disable=["parser", "lemmatizer", "attribute_ruler", "tagger"])


class PIIDetector:
    """
    Multi-layer hybrid PII detector combining Regex, spaCy NER, and Domain-Specific Heuristics.
    Detects minimum required PII types:
      - Full Names
      - Email Addresses
      - Phone Numbers
      - Company Names
      - Physical / Mailing Addresses
      - SSNs / Corporate Registration IDs (CIN, PAN)
      - Credit Card Numbers
      - Dates of Birth
      - IP Addresses
    """

    def __init__(self):
        self.nlp = nlp
        
        # Regex patterns for deterministic PII
        self.regex_patterns = {
            "EMAIL": re.compile(
                r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
                re.IGNORECASE
            ),
            "IP_ADDRESS": re.compile(
                r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
                r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
            ),
            "SSN": re.compile(
                r'\b\d{3}-\d{2}-\d{4}\b'
            ),
            "CIN_PAN": re.compile(
                r'\b[LU]\d{5}[A-Z]{2}\d{4}[A-Z]{3}\d{6}\b|\b[A-Z]{5}\d{4}[A-Z]{1}\b'
            ),
            "CREDIT_CARD": re.compile(
                r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|'
                r'3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|'
                r'(?:2131|1800|35\d{3})\d{11})\b'
            ),
            "DATE_OF_BIRTH": re.compile(
                r'\b(?:(?:0?[1-9]|[12][0-9]|3[01])[-/.](?:0?[1-9]|1[0-2])[-/.](?:19|20)\d{2}|'
                r'(?:19|20)\d{2}[-/.](?:0?[1-9]|1[0-2])[-/.](?:0?[1-9]|[12][0-9]|3[01])|'
                r'(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},\s+(?:19|20)\d{2})\b',
                re.IGNORECASE
            ),
            "PHONE": re.compile(
                r'(?:(?:\+|\b00)\d{1,3}[-.\s]?)?'  # Country code like +91
                r'(?:\(?\d{2,5}\)?[-.\s]?)'       # Area code
                r'\d{3,4}[-.\s]?\d{3,4}\b'         # Main subscriber digits
            )
        }

        # Keywords for address heuristic detection
        self.address_keywords = [
            "village", "taluka", "district", "street", "road", "avenue", "lane",
            "building", "tower", "floor", "suite", "flat", "plot", "chakan", "khed",
            "baner", "pune", "maharashtra", "mumbai", "delhi", "bengaluru", "chennai",
            "hyderabad", "kolkata", "pin", "postal code", "pincode"
        ]

    def _is_valid_phone(self, match_str: str, full_text: str, start: int, end: int) -> bool:
        """Filter out false positive numbers like dates, currency, statutory sections, CIN numbers."""
        digits_only = re.sub(r'\D', '', match_str)
        if len(digits_only) < 8 or len(digits_only) > 15:
            return False
        
        # Avoid matching years like 2025, 2013, page numbers
        if digits_only in ("2013", "2025", "2024", "2026", "410501", "411045"):
            return False

        # Context check (e.g. if preceded by Telephone, Tel, Phone, Mobile, +91, Fax)
        prefix = full_text[max(0, start - 25):start].lower()
        suffix = full_text[end:min(len(full_text), end + 15)].lower()
        
        trigger_words = ["telephone", "tel", "phone", "mobile", "fax", "contact", "+91", "call", "cell"]
        if any(w in prefix or w in suffix for w in trigger_words) or match_str.startswith("+"):
            return True
        
        # If 10 digits starting with 6,7,8,9 (Indian mobile) or 020/022 (landline)
        if len(digits_only) == 10 and digits_only[0] in "6789":
            return True
        if match_str.startswith("0") or match_str.startswith("+91") or match_str.startswith("91"):
            return True

        return False

    def detect(self, text: str, entity_types: List[str] = None) -> List[Dict[str, Any]]:
        if not text or len(text.strip()) < 3:
            return []

        # Fast pre-filter: PII requires uppercase letters, digits, @, or +
        if not any(c.isupper() or c.isdigit() or c in "@+" for c in text):
            return []

        entities = []

        # 1. Regex Detection
        for pii_type, pattern in self.regex_patterns.items():
            if entity_types and pii_type not in entity_types:
                continue
            for match in pattern.finditer(text):
                matched_text = match.group()
                start, end = match.span()

                # Phone validation filter
                if pii_type == "PHONE" and not self._is_valid_phone(matched_text, text, start, end):
                    continue

                entities.append({
                    "text": matched_text,
                    "type": pii_type,
                    "start": start,
                    "end": end,
                    "confidence": 0.98,
                    "source": "REGEX"
                })

        # 2. spaCy NER Detection (Only run if uppercase characters exist)
        if any(c.isupper() for c in text):
            doc = self.nlp(text)
            for ent in doc.ents:
                pii_type = None
                if ent.label_ == "PERSON":
                    pii_type = "PERSON"
                    if len(ent.text.strip()) <= 2:
                        continue
                elif ent.label_ in ("ORG"):
                    pii_type = "COMPANY"
                elif ent.label_ in ("GPE", "LOC", "FAC"):
                    pii_type = "ADDRESS"

                if pii_type and (not entity_types or pii_type in entity_types):
                    entities.append({
                        "text": ent.text,
                        "type": pii_type,
                        "start": ent.start_char,
                        "end": ent.end_char,
                        "confidence": 0.88,
                        "source": "NER"
                    })

        # 3. Domain Specific Heuristic Detection (Indian Corporate & Prospectus Patterns)
        # Promoters / Contact Person / Registered Office Heuristics
        promoter_match = re.search(r'OUR PROMOTERS:\s*([^\n]+)', text, re.IGNORECASE)
        if promoter_match and (not entity_types or "PERSON" in entity_types):
            names_block = promoter_match.group(1)
            # Split by comma or AND
            raw_names = re.split(r',\s*|\s+AND\s+', names_block)
            base_start = promoter_match.start(1)
            for name in raw_names:
                name_clean = name.strip()
                if len(name_clean) > 3 and "LIMITED" not in name_clean and "TRUST" not in name_clean:
                    n_start = text.find(name_clean, base_start)
                    if n_start != -1:
                        entities.append({
                            "text": name_clean,
                            "type": "PERSON",
                            "start": n_start,
                            "end": n_start + len(name_clean),
                            "confidence": 0.96,
                            "source": "HEURISTIC"
                        })

        # Resolve overlaps (keep highest confidence / longest match)
        entities = self._resolve_overlaps(entities)
        return entities

    def detect_batch(self, texts: List[str], entity_types: List[str] = None) -> List[List[Dict[str, Any]]]:
        """
        High-performance batch detection across multiple texts using spaCy nlp.pipe.
        Returns a list of entity lists for each corresponding text element.
        """
        results = [[] for _ in texts]
        if not texts:
            return results

        # 1. Fast pre-filter candidate texts
        candidate_indices = []
        candidate_texts = []
        for idx, text in enumerate(texts):
            if text and len(text.strip()) >= 3 and any(c.isupper() or c.isdigit() or c in "@+" for c in text):
                candidate_indices.append(idx)
                candidate_texts.append(text)

        if not candidate_texts:
            return results

        # 2. Vectorized Regex & Domain Heuristics
        for c_idx, text in zip(candidate_indices, candidate_texts):
            for pii_type, pattern in self.regex_patterns.items():
                if entity_types and pii_type not in entity_types:
                    continue
                for match in pattern.finditer(text):
                    matched_text = match.group()
                    start, end = match.span()
                    if pii_type == "PHONE" and not self._is_valid_phone(matched_text, text, start, end):
                        continue
                    results[c_idx].append({
                        "text": matched_text,
                        "type": pii_type,
                        "start": start,
                        "end": end,
                        "confidence": 0.98,
                        "source": "REGEX"
                    })

            promoter_match = re.search(r'OUR PROMOTERS:\s*([^\n]+)', text, re.IGNORECASE)
            if promoter_match and (not entity_types or "PERSON" in entity_types):
                names_block = promoter_match.group(1)
                raw_names = re.split(r',\s*|\s+AND\s+', names_block)
                base_start = promoter_match.start(1)
                for name in raw_names:
                    name_clean = name.strip()
                    if len(name_clean) > 3 and "LIMITED" not in name_clean and "TRUST" not in name_clean:
                        n_start = text.find(name_clean, base_start)
                        if n_start != -1:
                            results[c_idx].append({
                                "text": name_clean,
                                "type": "PERSON",
                                "start": n_start,
                                "end": n_start + len(name_clean),
                                "confidence": 0.96,
                                "source": "HEURISTIC"
                            })

        # 3. Batch spaCy NER via nlp.pipe
        ner_candidate_positions = []
        ner_texts = []
        for c_idx, text in zip(candidate_indices, candidate_texts):
            if any(c.isupper() for c in text):
                ner_candidate_positions.append(c_idx)
                ner_texts.append(text)

        if ner_texts:
            for c_idx, doc in zip(ner_candidate_positions, self.nlp.pipe(ner_texts, batch_size=32)):
                for ent in doc.ents:
                    pii_type = None
                    if ent.label_ == "PERSON":
                        pii_type = "PERSON"
                        if len(ent.text.strip()) <= 2:
                            continue
                    elif ent.label_ == "ORG":
                        pii_type = "COMPANY"
                    elif ent.label_ in ("GPE", "LOC", "FAC"):
                        pii_type = "ADDRESS"

                    if pii_type and (not entity_types or pii_type in entity_types):
                        results[c_idx].append({
                            "text": ent.text,
                            "type": pii_type,
                            "start": ent.start_char,
                            "end": ent.end_char,
                            "confidence": 0.88,
                            "source": "NER"
                        })

        # 4. Resolve overlaps for each result
        for idx in range(len(results)):
            if results[idx]:
                results[idx] = self._resolve_overlaps(results[idx])

        return results

    def _resolve_overlaps(self, entities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove overlapping entity spans, prioritizing higher confidence and longer spans."""
        if not entities:
            return []

        # Sort by start position, then by length descending, then confidence descending
        sorted_entities = sorted(
            entities,
            key=lambda x: (x["start"], -(x["end"] - x["start"]), -x["confidence"])
        )

        resolved = []
        last_end = -1

        for ent in sorted_entities:
            if ent["start"] >= last_end:
                resolved.append(ent)
                last_end = ent["end"]
            else:
                # Overlap detected. If current entity is strictly longer or higher confidence, replace last
                prev = resolved[-1]
                if (ent["end"] - ent["start"]) > (prev["end"] - prev["start"]) and ent["confidence"] > prev["confidence"]:
                    resolved[-1] = ent
                    last_end = ent["end"]

        return resolved
