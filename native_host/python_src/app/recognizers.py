"""Custom Presidio Recognizers for Thai (TH) and Multilingual PII Entities.

Integrates directly with `presidio_analyzer.PatternRecognizer` and `Pattern`
while providing checksum validation (e.g., Thai 13-digit National ID Modulo-11)
and context-aware detection for Thai & international PII.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from presidio_analyzer import EntityRecognizer, Pattern, PatternRecognizer, RecognizerResult
from presidio_analyzer.nlp_engine import NlpArtifacts


def validate_thai_national_id_checksum(raw_text: str) -> bool:
    """Validate a 13-digit Thai National ID using the official Modulo-11 algorithm."""
    digits = re.sub(r"\D", "", raw_text)
    if len(digits) != 13:
        return False
    # First digit cannot be 0 or 9 in standard Thai IDs (usually 1-8)
    if digits[0] == "0":
        return False
    total = sum(int(digits[i]) * (13 - i) for i in range(12))
    check_digit = (11 - (total % 11)) % 10
    return check_digit == int(digits[12])


class ThaiNationalIdRecognizer(PatternRecognizer):
    """Recognizes 13-digit Thai National ID cards (บัตรประจำตัวประชาชนไทย).

    Supports both formatted (e.g., 1-1005-01234-56-7 or 1 1005 01234 56 7)
    and unformatted 13-digit numbers, with Modulo-11 checksum verification.
    """

    PATTERNS = [
        Pattern(
            "TH_ID_FORMATTED",
            r"(?<!\d)[1-8][-\s]?\d{4}[-\s]?\d{5}[-\s]?\d{2}[-\s]?\d(?!\d)",
            0.65,
        ),
        Pattern(
            "TH_ID_PLAIN_13",
            r"(?<!\d)[1-8]\d{12}(?!\d)",
            0.55,
        ),
    ]

    CONTEXT = [
        "บัตรประชาชน",
        "เลขบัตร",
        "เลขประจำตัวประชาชน",
        "เลขที่บัตร",
        "ปชช",
        "citizen id",
        "national id",
        "thai id",
        "id card",
        "เลขประจำตัว",
    ]

    def __init__(
        self,
        supported_language: str = "en",
        strict_checksum: bool = False,
    ) -> None:
        self.strict_checksum = strict_checksum
        super().__init__(
            supported_entity="TH_NATIONAL_ID",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language=supported_language,
            name="ThaiNationalIdRecognizer",
        )

    def validate_result(self, pattern_text: str) -> Optional[bool]:
        """Boost score to 1.0 when Modulo-11 checksum passes."""
        digits = re.sub(r"\D", "", pattern_text)
        if len(digits) != 13:
            return False
        if validate_thai_national_id_checksum(digits):
            return True
        # If strict_checksum is False, still allow formatted IDs like 1-2345-67890-12-3
        # in mock/test data by returning None (keeps base pattern score),
        # or reject if strict_checksum is True.
        if self.strict_checksum:
            return False
        if re.match(r"^[1-8][-\s]\d{4}[-\s]\d{5}[-\s]\d{2}[-\s]\d$", pattern_text.strip()):
            return None
        return None


class ThaiPhoneRecognizer(PatternRecognizer):
    """Recognizes Thai mobile (06x, 08x, 09x) and landline (02, 03x, 04x, 05x, 07x) numbers,
    including +66 international format.
    """

    PATTERNS = [
        Pattern(
            "TH_MOBILE_DOMESTIC",
            r"(?<!\d)0[689]\d[-\s]?\d{3}[-\s]?\d{4}(?!\d)",
            0.85,
        ),
        Pattern(
            "TH_MOBILE_INTL",
            r"(?<!\w)\+66[-\s]?[689]\d[-\s]?\d{3}[-\s]?\d{4}(?!\d)",
            0.95,
        ),
        Pattern(
            "TH_LANDLINE_BKK",
            r"(?<!\d)02[-\s]?\d{3}[-\s]?\d{4}(?!\d)",
            0.80,
        ),
        Pattern(
            "TH_LANDLINE_PROVINCE",
            r"(?<!\d)0[3457]\d[-\s]?\d{3}[-\s]?\d{3}(?!\d)",
            0.75,
        ),
    ]

    CONTEXT = [
        "เบอร์",
        "เบอร์โทร",
        "โทรศัพท์",
        "มือถือ",
        "ติดต่อ",
        "โทร",
        "tel",
        "phone",
        "mobile",
        "contact",
    ]

    def __init__(self, supported_language: str = "en") -> None:
        super().__init__(
            supported_entity="TH_PHONE_NUMBER",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language=supported_language,
            name="ThaiPhoneRecognizer",
        )


class ThaiPersonNameRecognizer(EntityRecognizer):
    """Recognizes Thai person names via Thai honorific prefixes (คำนำหน้าชื่อ)
    and context labels (ชื่อ-นามสกุล).

    Crucial Note: Returns ONLY the person's name span (or prefix + name based on setting),
    preventing prefix leakage while cleanly capturing Thai first + last names.
    """

    HONORIFICS = [
        r"นางสาว",
        r"น\.ส\.",
        r"นาย",
        r"นาง",
        r"ด\.ช\.",
        r"ด\.ญ\.",
        r"เด็กชาย",
        r"เด็กหญิง",
        r"คุณ",
        r"ผศ\.ดร\.",
        r"รศ\.ดร\.",
        r"ศ\.ดร\.",
        r"ดร\.",
        r"ผศ\.",
        r"รศ\.",
        r"ศ\.",
        r"นพ\.",
        r"พญ\.",
        r"ทพ\.",
        r"ทพญ\.",
        r"ภก\.",
        r"ภญ\.",
        r"สพ\.ญ\.",
        r"น\.สพ\.",
        r"ว่าที่\s*ร\.ต\.",
        r"พล\.ต\.อ\.",
        r"พล\.ต\.ท\.",
        r"พล\.ต\.ต\.",
        r"พล\.อ\.",
        r"พล\.ท\.",
        r"พล\.ต\.",
        r"พ\.ต\.อ\.",
        r"พ\.ต\.ท\.",
        r"พ\.ต\.ต\.",
        r"ร\.ต\.อ\.",
        r"ร\.ต\.ท\.",
        r"ร\.ต\.ต\.",
    ]

    # Thai character block: \u0E01-\u0E4E
    THAI_WORD = r"[\u0E01-\u0E4E]{2,35}"

    def __init__(self, supported_language: str = "en", include_honorific: bool = False) -> None:
        super().__init__(
            supported_entities=["TH_PERSON_NAME"],
            supported_language=supported_language,
            name="ThaiPersonNameRecognizer",
        )
        self.include_honorific = include_honorific
        honorific_union = "|".join(self.HONORIFICS)
        # Pattern 1: Honorific + First Name (+ optional Middle/Last Name up to 3 parts)
        self.honorific_regex = re.compile(
            rf"(?P<prefix>{honorific_union})\s*(?P<name>{self.THAI_WORD}(?:\s+{self.THAI_WORD}){{0,2}})"
        )
        # Pattern 2: Explicit label e.g. "ชื่อ-นามสกุล: สมชาย ใจดี" or "ชื่อ : สมศรี มีสุข"
        self.label_regex = re.compile(
            rf"(?:ชื่อ-นามสกุล|ชื่อ-สกุล|ชื่อผู้ติดต่อ|ชื่อลูกค้า|ผู้รับเงิน|ผู้โอน|ผู้เอาประกัน)\s*[:：]?\s*(?:{honorific_union})?\s*(?P<name>{self.THAI_WORD}(?:\s+{self.THAI_WORD}){{1,2}})"
        )

    def load(self) -> None:
        pass

    # Words that might follow a name on the same line and should not be treated as a surname
    STOP_SURNAME_WORDS = {
        "โทร",
        "เบอร์",
        "เบอร์โทร",
        "ติดต่อ",
        "ที่อยู่",
        "เลขที่",
        "บ้านเลขที่",
        "อีเมล",
        "แผนก",
        "ตำแหน่ง",
        "อายุ",
        "เพศ",
        "บัตร",
        "เลขบัตร",
        "บัญชี",
        "ธนาคาร",
        "วันที่",
        "เวลา",
        "จำนวน",
        "บาท",
        "รหัส",
        "หมายเหตุ",
    }

    def analyze(
        self,
        text: str,
        entities: List[str],
        nlp_artifacts: Optional[NlpArtifacts] = None,
    ) -> List[RecognizerResult]:
        if "TH_PERSON_NAME" not in entities:
            return []

        results: List[RecognizerResult] = []
        seen_spans = set()

        for match in self.honorific_regex.finditer(text):
            name_part = match.group("name")
            parts = name_part.split()
            while len(parts) > 1 and parts[-1] in self.STOP_SURNAME_WORDS:
                parts.pop()
            trimmed_name = " ".join(parts)
            # Compute exact end position in text for the kept parts
            last_part = parts[-1]
            # Find where the kept parts end inside match.group("name")
            if len(parts) < len(name_part.split()):
                # Locate end of the last kept token
                pos = 0
                for p in parts:
                    idx = name_part.find(p, pos)
                    pos = idx + len(p)
                end = match.start("name") + pos
            else:
                end = match.end("name")
            start = match.start() if self.include_honorific else match.start("name")

            if (start, end) not in seen_spans:
                seen_spans.add((start, end))
                results.append(
                    RecognizerResult(
                        entity_type="TH_PERSON_NAME",
                        start=start,
                        end=end,
                        score=0.90,
                    )
                )

        for match in self.label_regex.finditer(text):
            start = match.start("name")
            end = match.end("name")
            if not any(s <= start and end <= e for s, e in seen_spans):
                seen_spans.add((start, end))
                results.append(
                    RecognizerResult(
                        entity_type="TH_PERSON_NAME",
                        start=start,
                        end=end,
                        score=0.88,
                    )
                )

        return results


class ThaiBankAccountRecognizer(PatternRecognizer):
    """Recognizes Thai bank account numbers (10-12 digits formatted as xxx-x-xxxxx-x or with bank context)."""

    PATTERNS = [
        # Standard Thai 10-digit bank format: 123-4-56789-0 or 123-456-7890
        Pattern(
            "TH_BANK_DASHED_10",
            r"(?<!\d)\d{3}-\d-\d{5}-\d(?!\d)",
            0.88,
        ),
        Pattern(
            "TH_BANK_DASHED_ALT",
            r"(?<!\d)\d{3}-\d{3}-\d{4}(?!\d)",
            0.55,
        ),
        # 10-digit plain number (relies on context boost or medium confidence)
        Pattern(
            "TH_BANK_PLAIN_10",
            r"(?<!\d)[1-9]\d{9}(?!\d)",
            0.45,
        ),
    ]

    CONTEXT = [
        "บัญชี",
        "เลขที่บัญชี",
        "เลขบัญชี",
        "ธนาคาร",
        "กสิกร",
        "กสิกรไทย",
        "ไทยพาณิชย์",
        "กรุงเทพ",
        "กรุงไทย",
        "กรุงศรี",
        "ทหารไทยธนชาต",
        "ออมสิน",
        "เกียรตินาคิน",
        "ทิสโก้",
        "ซีไอเอ็มบี",
        "ยูโอบี",
        "ธกส",
        "ธอส",
        "kbank",
        "scb",
        "bbl",
        "ktb",
        "bay",
        "ttb",
        "gsb",
        "uob",
        "cimb",
        "bank account",
        "account no",
        "a/c",
    ]

    def __init__(self, supported_language: str = "en") -> None:
        super().__init__(
            supported_entity="TH_BANK_ACCOUNT",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language=supported_language,
            name="ThaiBankAccountRecognizer",
        )


class ThaiAddressRecognizer(PatternRecognizer):
    """Recognizes Thai address components (บ้านเลขที่, หมู่, ซอย, ถนน, ตำบล/แขวง, อำเภอ/เขต, จังหวัด, รหัสไปรษณีย์)."""

    PATTERNS = [
        Pattern(
            "TH_FULL_ADDRESS",
            r"(?:บ้านเลขที่|เลขที่)\s*\d+(?:/\d+)?(?:\s*(?:หมู่(?:ที่)?|ม\.)\s*\d+)?"
            r"(?:\s*(?:ซอย|ซ\.|ถนน|ถ\.|ต\.|ตำบล|แขวง|อ\.|อำเภอ|เขต|จ\.|จังหวัด|กทม\.?|กรุงเทพ(?:มหานคร)?)[^\n,;]{0,80})?"
            r"(?:\s*[1-9]\d{4})?",
            0.85,
        ),
        Pattern(
            "TH_SUBDISTRICT_PROVINCE_ZIP",
            r"(?:ต\.|ตำบล|แขวง)\s*[\u0E01-\u0E4E]+\s+(?:อ\.|อำเภอ|เขต)\s*[\u0E01-\u0E4E]+\s+(?:จ\.|จังหวัด)?\s*[\u0E01-\u0E4E.]+\s*(?:[1-9]\d{4})?",
            0.85,
        ),
    ]

    CONTEXT = [
        "ที่อยู่",
        "บ้านเลขที่",
        "จัดส่ง",
        "ตำบล",
        "อำเภอ",
        "จังหวัด",
        "แขวง",
        "เขต",
        "รหัสไปรษณีย์",
        "address",
    ]

    def __init__(self, supported_language: str = "en") -> None:
        super().__init__(
            supported_entity="TH_ADDRESS",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language=supported_language,
            name="ThaiAddressRecognizer",
        )


class ThaiLaserIdRecognizer(PatternRecognizer):
    """Recognizes Thai National ID Card Back Laser Code (e.g., ME0-1234567-89 or JT1234567890)."""

    PATTERNS = [
        Pattern(
            "TH_LASER_ID",
            r"(?<![A-Z0-9])[A-Z]{2}\d-?\d{7}-?\d{2}(?!\d)",
            0.85,
        ),
    ]

    CONTEXT = [
        "หลังบัตร",
        "เลขหลังบัตร",
        "laser id",
        "laser code",
        "รหัสหลังบัตร",
    ]

    def __init__(self, supported_language: str = "en") -> None:
        super().__init__(
            supported_entity="TH_LASER_ID",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language=supported_language,
            name="ThaiLaserIdRecognizer",
        )


class ThaiLicensePlateRecognizer(PatternRecognizer):
    """Recognizes Thai vehicle license plates (e.g., 1กข 1234, กข-1234)."""

    PATTERNS = [
        Pattern(
            "TH_LICENSE_PLATE",
            r"(?<!\w)(?:[1-9]\s*)?[ก-ฮ]{2,3}[-\s]\d{1,4}(?!\d)",
            0.78,
        ),
    ]

    CONTEXT = [
        "ทะเบียน",
        "ทะเบียนรถ",
        "ป้ายทะเบียน",
        "รถยนต์",
        "รถจักรยานยนต์",
        "license plate",
    ]

    def __init__(self, supported_language: str = "en") -> None:
        super().__init__(
            supported_entity="TH_LICENSE_PLATE",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language=supported_language,
            name="ThaiLicensePlateRecognizer",
        )


class ApiKeySecretRecognizer(PatternRecognizer):
    """Recognizes API keys, cloud secrets, JWTs, private keys, and password assignments
    (OpenAI, Anthropic, AWS, GitHub, Google Cloud, Slack, Stripe, JWT, Generic Secrets).
    """

    PATTERNS = [
        Pattern(
            "OPENAI_OR_ANTHROPIC_KEY",
            r"\bsk-(?:proj-|ant-api\d{2}-)?[A-Za-z0-9_\-]{16,120}\b",
            0.98,
        ),
        Pattern(
            "AWS_ACCESS_KEY",
            r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
            0.98,
        ),
        Pattern(
            "GITHUB_TOKEN",
            r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,100}\b|\bgithub_pat_[A-Za-z0-9_]{20,120}\b",
            0.98,
        ),
        Pattern(
            "GOOGLE_API_KEY",
            r"\bAIza[0-9A-Za-z\-_]{35}\b",
            0.98,
        ),
        Pattern(
            "SLACK_OR_STRIPE_TOKEN",
            r"\b(?:xox[baprs]-[0-9A-Za-z\-]{10,80}|(?:sk|pk)_(?:live|test)_[0-9A-Za-z]{16,90})\b",
            0.96,
        ),
        Pattern(
            "JWT_BEARER_TOKEN",
            r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
            0.95,
        ),
        Pattern(
            "GENERIC_SECRET_ASSIGNMENT",
            r"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token|password|passwd|pwd|client[_-]?secret)\s*[:=]\s*['\"][^'\"]{6,120}['\"]",
            0.90,
        ),
    ]

    CONTEXT = [
        "api_key",
        "apikey",
        "secret",
        "token",
        "bearer",
        "password",
        "authorization",
        "รหัสผ่าน",
        "คีย์",
    ]

    def __init__(self, supported_language: str = "en") -> None:
        super().__init__(
            supported_entity="API_KEY_SECRET",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language=supported_language,
            name="ApiKeySecretRecognizer",
        )


def build_default_custom_recognizers(language: str = "en") -> List[EntityRecognizer]:
    """Return all built-in Thai, Secret & enhanced recognizers for registration in Presidio."""
    return [
        ThaiNationalIdRecognizer(supported_language=language),
        ThaiPhoneRecognizer(supported_language=language),
        ThaiPersonNameRecognizer(supported_language=language, include_honorific=False),
        ThaiBankAccountRecognizer(supported_language=language),
        ThaiAddressRecognizer(supported_language=language),
        ThaiLaserIdRecognizer(supported_language=language),
        ThaiLicensePlateRecognizer(supported_language=language),
        ApiKeySecretRecognizer(supported_language=language),
    ]


def create_user_pattern_recognizer(
    entity_type: str,
    regex_pattern: str,
    score: float = 0.85,
    context_words: Optional[List[str]] = None,
    deny_list: Optional[List[str]] = None,
    language: str = "en",
) -> PatternRecognizer:
    """Create a dynamic Presidio PatternRecognizer from user-supplied regex or deny-list."""
    patterns = []
    if regex_pattern and regex_pattern.strip():
        patterns.append(Pattern(f"CUSTOM_{entity_type}", regex_pattern.strip(), score))

    cleaned_deny = [w.strip() for w in (deny_list or []) if w.strip()]
    cleaned_ctx = [w.strip() for w in (context_words or []) if w.strip()]

    return PatternRecognizer(
        supported_entity=entity_type.strip().upper(),
        patterns=patterns if patterns else None,
        deny_list=cleaned_deny if cleaned_deny else None,
        context=cleaned_ctx if cleaned_ctx else None,
        supported_language=language,
        name=f"UserCustom_{entity_type.strip().upper()}",
    )
