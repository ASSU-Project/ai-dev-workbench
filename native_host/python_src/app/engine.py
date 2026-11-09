"""Presidio Analysis & Anonymization Engine for Desktop PII Masking.

Wraps `presidio_analyzer.AnalyzerEngine` and `presidio_anonymizer.AnonymizerEngine`,
integrating:
- English & Multilingual NLP recognizers (via spaCy `en_core_web_sm` or lightweight regex mode)
- Thai PII custom recognizers (`TH_NATIONAL_ID`, `TH_PHONE_NUMBER`, `TH_PERSON_NAME`,
  `TH_BANK_ACCOUNT`, `TH_ADDRESS`, `TH_LASER_ID`, `TH_LICENSE_PLATE`)
- User-defined custom Regex & Deny-list recognizers for any language
- Full suite of Anonymization Operators:
  1. `keep_prefix_suffix`: Keep N chars at front & M chars at back, mask middle (Thai grapheme aware!)
  2. `mask_prefix_suffix`: Mask N chars at front & M chars at back, keep middle
  3. `replace`: Replace with `<ENTITY_TYPE>` or custom template (via Presidio Anonymizer)
  4. `mask`: Standard Presidio `mask` operator (mask N chars from start or end)
  5. `redact`: Remove completely or replace with `[REDACTED]` (via Presidio Anonymizer)
  6. `hash`: Cryptographic hash SHA-256 / SHA-512 / MD5 with optional salt & truncation
  7. `token`: Reversible consistent token mapping (`[PERSON_1]`, `[TH_PHONE_NUMBER_1]`)
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
import threading
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from presidio_analyzer import AnalyzerEngine, PatternRecognizer, RecognizerRegistry, RecognizerResult
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from app.recognizers import (
    build_default_custom_recognizers,
    create_user_pattern_recognizer,
)

DEFAULT_PARALLEL_WORKERS = max(4, min(16, (os.cpu_count() or 4) * 2))


# Entity Metadata Catalog for UI Display (Grouped into 5 clean domain groups)
ENTITY_CATALOG: List[Dict[str, Any]] = [
    # Group 1: Thai Identity & Personal Data
    {
        "id": "TH_PERSON_NAME",
        "label": "ชื่อ-นามสกุลไทย (Thai Person Name)",
        "category": "Thai PII",
        "group": "Thai Identity",
        "description": "ตรวจจับชื่อ-นามสกุลภาษาไทยจากคำนำหน้าชื่อ (นาย/นาง/นางสาว/คุณ/ดร./นพ.) และป้ายกำกับ",
        "default_enabled": True,
    },
    {
        "id": "TH_NATIONAL_ID",
        "label": "เลขบัตรประชาชน 13 หลัก (Thai National ID)",
        "category": "Thai PII",
        "group": "Thai Identity",
        "description": "เลขประจำตัวประชาชนไทย 13 หลัก พร้อมตรวจสอบสูตร Modulo-11 Checksum",
        "default_enabled": True,
    },
    {
        "id": "TH_LASER_ID",
        "label": "เลขหลังบัตรประชาชน (Laser ID)",
        "category": "Thai PII",
        "group": "Thai Identity",
        "description": "รหัสกำกับหลังบัตรประชาชน 12 หลัก (เช่น ME0-1234567-89)",
        "default_enabled": True,
    },
    {
        "id": "TH_PHONE_NUMBER",
        "label": "เบอร์โทรศัพท์ไทย (Thai Phone Number)",
        "category": "Thai PII",
        "group": "Thai Identity",
        "description": "เบอร์มือถือ (06x/08x/09x, +66) และเบอร์พื้นฐาน (02/03x/05x/07x)",
        "default_enabled": True,
    },
    {
        "id": "TH_ADDRESS",
        "label": "ที่อยู่ภาษาไทย (Thai Address)",
        "category": "Thai PII",
        "group": "Thai Identity",
        "description": "บ้านเลขที่ หมู่ที่ ซอย ถนน ตำบล/แขวง อำเภอ/เขต จังหวัด และรหัสไปรษณีย์",
        "default_enabled": True,
    },
    {
        "id": "TH_LICENSE_PLATE",
        "label": "ทะเบียนรถยนต์ไทย (Thai License Plate)",
        "category": "Thai PII",
        "group": "Thai Identity",
        "description": "ป้ายทะเบียนรถยนต์และรถจักรยานยนต์ไทย (เช่น 1กข 4567, กข-1234)",
        "default_enabled": True,
    },
    # Group 2: Financial & Banking
    {
        "id": "TH_BANK_ACCOUNT",
        "label": "เลขบัญชีธนาคารไทย (Thai Bank Account)",
        "category": "Thai PII",
        "group": "Financial & Banking",
        "description": "เลขบัญชีธนาคารไทย 10 หลัก (รูปแบบมีขีดคั่น หรือมีบริบทชื่อธนาคาร)",
        "default_enabled": True,
    },
    {
        "id": "CREDIT_CARD",
        "label": "หมายเลขบัตรเครดิต/เดบิต (Credit Card)",
        "category": "Global PII",
        "group": "Financial & Banking",
        "description": "หมายเลขบัตร Visa, MasterCard, Amex, JCB พร้อมตรวจสอบ Luhn Checksum",
        "default_enabled": True,
    },
    {
        "id": "IBAN_CODE",
        "label": "รหัสเดินบัญชีสากล (IBAN Code)",
        "category": "Global PII",
        "group": "Financial & Banking",
        "description": "International Bank Account Number (IBAN)",
        "default_enabled": True,
    },
    {
        "id": "CRYPTO",
        "label": "กระเป๋าสินทรัพย์ดิจิทัล (Crypto Wallet)",
        "category": "Global PII",
        "group": "Financial & Banking",
        "description": "ที่อยู่กระเป๋า Bitcoin / Cryptocurrency",
        "default_enabled": True,
    },
    # Group 3: Global Identity & Contact
    {
        "id": "PERSON",
        "label": "ชื่อบุคคลภาษาอังกฤษ (English Person Name)",
        "category": "Global PII",
        "group": "Global Identity & Contact",
        "description": "ชื่อ-นามสกุลภาษาอังกฤษ ตรวจจับด้วย Presidio spaCy NER",
        "default_enabled": True,
    },
    {
        "id": "EMAIL_ADDRESS",
        "label": "อีเมล (Email Address)",
        "category": "Global PII",
        "group": "Global Identity & Contact",
        "description": "ที่อยู่อีเมลตามมาตรฐาน RFC-5322",
        "default_enabled": True,
    },
    {
        "id": "PHONE_NUMBER",
        "label": "เบอร์โทรศัพท์สากล (International Phone)",
        "category": "Global PII",
        "group": "Global Identity & Contact",
        "description": "หมายเลขโทรศัพท์ต่างประเทศ",
        "default_enabled": True,
    },
    {
        "id": "LOCATION",
        "label": "สถานที่/ที่อยู่ภาษาอังกฤษ (English Location)",
        "category": "Global PII",
        "group": "Global Identity & Contact",
        "description": "ชื่อเมือง รัฐ ประเทศ และสถานที่ภาษาอังกฤษ (NER)",
        "default_enabled": True,
    },
    {
        "id": "US_SSN",
        "label": "เลขประกันสังคมสหรัฐฯ (US SSN)",
        "category": "Global PII",
        "group": "Global Identity & Contact",
        "description": "หมายเลข US Social Security Number 9 หลัก",
        "default_enabled": True,
    },
    {
        "id": "US_PASSPORT",
        "label": "หมายเลขหนังสือเดินทาง (Passport Number)",
        "category": "Global PII",
        "group": "Global Identity & Contact",
        "description": "หมายเลขหนังสือเดินทางสากล",
        "default_enabled": True,
    },
    {
        "id": "DATE_TIME",
        "label": "วันที่และเวลา / วันเกิด (Date & Time)",
        "category": "Global PII",
        "group": "Global Identity & Contact",
        "description": "ข้อมูลวันที่ เวลา หรือวันเดือนปีเกิด",
        "default_enabled": False,
    },
    # Group 4: Credentials, Secrets & Network
    {
        "id": "API_KEY_SECRET",
        "label": "API Keys, Tokens & รหัสผ่าน (OpenAI/AWS/GitHub/JWT)",
        "category": "Thai PII",
        "group": "Credentials & Network",
        "description": "ตรวจจับ OpenAI sk-..., AWS AKIA..., GitHub ghp_..., Google AIza..., JWT และรหัสผ่านในโค้ด",
        "default_enabled": True,
    },
    {
        "id": "IP_ADDRESS",
        "label": "หมายเลข IP Address (IPv4 / IPv6)",
        "category": "Global PII",
        "group": "Credentials & Network",
        "description": "หมายเลข IP เครือข่ายและเซิร์ฟเวอร์",
        "default_enabled": True,
    },
    {
        "id": "URL",
        "label": "ลิงก์เว็บไซต์ (URL / Domain Link)",
        "category": "Global PII",
        "group": "Credentials & Network",
        "description": "ลิงก์ HTTP/HTTPS และชื่อโดเมน",
        "default_enabled": False,
    },
]


def split_grapheme_clusters(text: str) -> List[str]:
    """Split text into user-perceived characters (grapheme clusters).

    Crucial for Thai script: Thai combining vowels (e.g. ั ิ ี ึ ื ุ ู ็)
    and tone marks (่ ้ ๊ ๋ ์) attach to the base consonant. Grouping them
    ensures that 'เว้นหน้า 2 ตัวอักษร เว้นหลัง 3 ตัวอักษร' counts actual
    visible Thai characters rather than splitting a tone mark from its consonant.
    """
    if not text:
        return []
    clusters: List[str] = []
    for ch in text:
        # Mn = Nonspacing_Mark (Thai upper/lower vowels, tone marks, thanthakhat)
        # Mc = Spacing_Mark, Me = Enclosing_Mark
        # Also Thai Sara Am (\u0E33) is Lo but behaves as part of the syllable if preceded by tone mark
        cat = unicodedata.category(ch)
        if clusters and (cat in ("Mn", "Mc", "Me") or ch == "\u0e33"):
            clusters[-1] += ch
        else:
            clusters.append(ch)
    return clusters


SEPARATOR_CHARS = set(" -_./\\@:+(),[]")


def apply_keep_prefix_suffix(
    text: str,
    keep_start: int = 2,
    keep_end: int = 3,
    mask_char: str = "*",
    preserve_separators: bool = False,
    fixed_mask_len: int = 0,
    smart_short_fallback: bool = True,
) -> str:
    """Keep `keep_start` characters at the front and `keep_end` characters at the back,
    masking everything in the middle.

    Example:
      - `081-234-5678` (keep_start=2, keep_end=3, preserve_separators=False) -> `08*******678`
      - `081-234-5678` (keep_start=2, keep_end=3, preserve_separators=True)  -> `08*-***-*678`
      - `สมชาย ใจดีมาก` (keep_start=2, keep_end=3) -> `สม*******มาก`
    """
    if not text:
        return text
    mask_unit = (mask_char or "*")[0]
    keep_start = max(0, int(keep_start))
    keep_end = max(0, int(keep_end))

    clusters = split_grapheme_clusters(text)
    n = len(clusters)

    if n == 0:
        return text

    eff_start = keep_start
    eff_end = keep_end

    # Handle case where string is shorter than or equal to keep_start + keep_end
    if eff_start + eff_end >= n:
        if not smart_short_fallback:
            return text
        # Smart fallback so short PII never stays 100% unmasked:
        if n == 1:
            return mask_unit
        elif n == 2:
            eff_start = 1 if keep_start > 0 else 0
            eff_end = 0
        elif n == 3:
            eff_start = 1 if keep_start > 0 else 0
            eff_end = 1 if (keep_end > 0 and eff_start == 0) else 0
        else:
            # n >= 4: keep at most 1 at start and 1 at end so middle is masked
            eff_start = min(keep_start, 1)
            eff_end = min(keep_end, 1)

    prefix = "".join(clusters[:eff_start])
    suffix = "".join(clusters[n - eff_end :]) if eff_end > 0 else ""
    middle_clusters = clusters[eff_start : n - eff_end if eff_end > 0 else n]

    if fixed_mask_len and fixed_mask_len > 0:
        middle_masked = mask_unit * int(fixed_mask_len)
    elif preserve_separators:
        middle_masked = "".join(
            c if c in SEPARATOR_CHARS else mask_unit for c in middle_clusters
        )
    else:
        middle_masked = mask_unit * len(middle_clusters)

    return f"{prefix}{middle_masked}{suffix}"


def apply_mask_prefix_suffix(
    text: str,
    mask_start: int = 2,
    mask_end: int = 3,
    mask_char: str = "*",
    preserve_separators: bool = False,
) -> str:
    """Mask `mask_start` characters at the front and `mask_end` characters at the back,
    keeping the middle characters visible.
    """
    if not text:
        return text
    mask_unit = (mask_char or "*")[0]
    mask_start = max(0, int(mask_start))
    mask_end = max(0, int(mask_end))

    clusters = split_grapheme_clusters(text)
    n = len(clusters)

    if mask_start + mask_end >= n:
        if preserve_separators:
            return "".join(c if c in SEPARATOR_CHARS else mask_unit for c in clusters)
        return mask_unit * n

    front_clusters = clusters[:mask_start]
    middle_clusters = clusters[mask_start : n - mask_end if mask_end > 0 else n]
    back_clusters = clusters[n - mask_end :] if mask_end > 0 else []

    def _mask_list(items: List[str]) -> str:
        if preserve_separators:
            return "".join(c if c in SEPARATOR_CHARS else mask_unit for c in items)
        return mask_unit * len(items)

    return f"{_mask_list(front_clusters)}{''.join(middle_clusters)}{_mask_list(back_clusters)}"


@dataclass
class MaskingConfig:
    """Configuration for a PII analysis and masking operation."""

    #Operator mode:
    # - "keep_prefix_suffix" (เว้นหน้า N ตัว เว้นหลัง M ตัว)
    # - "mask_prefix_suffix" (ปิดหน้า N ตัว ปิดหลัง M ตัว)
    # - "replace"            (แทนที่ด้วย <ENTITY_TYPE> หรือ custom text)
    # - "mask"               (Presidio standard mask from start or end)
    # - "redact"             (ลบทิ้ง หรือ [REDACTED])
    # - "hash"               (SHA-256 / SHA-512 / MD5)
    # - "token"              (Reversible Token Mapping เช่น [PERSON_1])
    mode: str = "keep_prefix_suffix"

    # Parameters for keep_prefix_suffix / mask_prefix_suffix / mask
    keep_start: int = 2
    keep_end: int = 3
    mask_start: int = 2
    mask_end: int = 3
    mask_char: str = "*"
    preserve_separators: bool = False
    fixed_mask_len: int = 0
    smart_short_fallback: bool = True

    # Parameters for Presidio standard "mask" operator
    chars_to_mask: int = 6
    from_end: bool = True

    # Parameters for "replace" operator
    replace_template: str = "<{entity_type}>"

    # Parameters for "redact" operator
    redact_marker: str = ""  # Empty string = complete removal, or e.g. "[REDACTED]"

    # Parameters for "hash" operator
    hash_type: str = "sha256"  # sha256, sha512, md5
    hash_salt: str = ""
    hash_length: int = 12  # 0 = full hash

    # Detection settings
    score_threshold: float = 0.45
    entities: Optional[List[str]] = None

    # Optional per-entity mode overrides:
    # e.g. {"TH_NATIONAL_ID": {"mode": "keep_prefix_suffix", "keep_start": 1, "keep_end": 4}}
    entity_overrides: Dict[str, Dict[str, Any]] = field(default_factory=dict)


class ReversibleTokenizer:
    """Maintains consistent bidirectional mapping between original PII strings and tokens
    such as `[PERSON_1]`, `[TH_PHONE_NUMBER_1]` across an entire document or Excel file.
    Thread-safe for parallel execution.
    """

    def __init__(self, existing_map: Optional[Dict[str, str]] = None) -> None:
        self._lock = threading.Lock()
        # token -> original_value
        self.token_to_original: Dict[str, str] = dict(existing_map or {})
        # (entity_type, normalized_original) -> token
        self._lookup: Dict[Tuple[str, str], str] = {}
        self._counters: Dict[str, int] = {}

        for token, orig in self.token_to_original.items():
            # Parse e.g. [PERSON_1]
            clean = token.strip("[]<>")
            if "_" in clean:
                etype, idx_str = clean.rsplit("_", 1)
                if idx_str.isdigit():
                    idx = int(idx_str)
                    self._counters[etype] = max(self._counters.get(etype, 0), idx)
                    self._lookup[(etype, orig.strip())] = token

    def get_token(self, entity_type: str, original_text: str) -> str:
        key = (entity_type, original_text.strip())
        with self._lock:
            if key in self._lookup:
                return self._lookup[key]
            next_idx = self._counters.get(entity_type, 0) + 1
            self._counters[entity_type] = next_idx
            token = f"[{entity_type}_{next_idx}]"
            self._lookup[key] = token
            self.token_to_original[token] = original_text
            return token

    @staticmethod
    def restore_text(text: str, token_map: Dict[str, str]) -> Tuple[str, int]:
        """Restore a tokenized string using `token_map` (token -> original_value)."""
        if not text or not token_map:
            return text, 0
        restored = text
        count = 0
        # Sort tokens by length descending so [PERSON_10] is replaced before [PERSON_1]
        for token in sorted(token_map.keys(), key=len, reverse=True):
            original = token_map[token]
            if token in restored:
                occurrences = restored.count(token)
                restored = restored.replace(token, str(original))
                count += occurrences
        return restored, count


class PresidioMaskingEngine:
    """Core service combining Microsoft / Data-Privacy-Stack Presidio Analyzer & Anonymizer
    with Thai, English, and custom multi-language PII support.
    """

    def __init__(self) -> None:
        self.anonymizer = AnonymizerEngine()
        self.user_custom_rules: List[Dict[str, Any]] = []
        self._analyzer: Optional[AnalyzerEngine] = None
        self.nlp_mode: str = "spacy_en_sm"
        self.max_workers: int = DEFAULT_PARALLEL_WORKERS
        self._executor = ThreadPoolExecutor(max_workers=self.max_workers)
        self._analysis_cache: Dict[Tuple[str, Tuple[str, ...], float], List[RecognizerResult]] = {}
        self._cache_lock = threading.Lock()
        self._init_analyzer()

    def _init_analyzer(self) -> None:
        """Initialize Presidio AnalyzerEngine with spaCy `en_core_web_sm` and custom recognizers."""
        try:
            import en_core_web_sm  # Explicit import for PyInstaller bundling
            from presidio_analyzer.nlp_engine import SpacyNlpEngine

            model_path = str(en_core_web_sm.__path__[0])
            try:
                configuration = {
                    "nlp_engine_name": "spacy",
                    "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
                }
                provider = NlpEngineProvider(nlp_configuration=configuration)
                nlp_engine = provider.create_engine()
            except Exception:
                # Fallback for frozen PyInstaller bundle using direct package path
                nlp_engine = SpacyNlpEngine(models=[{"lang_code": "en", "model_name": model_path}])
                nlp_engine.load()

            registry = RecognizerRegistry()
            registry.load_predefined_recognizers(nlp_engine=nlp_engine)

            # Register Thai & regional custom recognizers
            for rec in build_default_custom_recognizers(language="en"):
                registry.add_recognizer(rec)

            # Re-register any user-defined custom recognizers
            for rule in self.user_custom_rules:
                rec = create_user_pattern_recognizer(
                    entity_type=rule["entity_type"],
                    regex_pattern=rule.get("regex_pattern", ""),
                    score=float(rule.get("score", 0.85)),
                    context_words=rule.get("context_words"),
                    deny_list=rule.get("deny_list"),
                )
                registry.add_recognizer(rec)

            self._analyzer = AnalyzerEngine(
                registry=registry,
                nlp_engine=nlp_engine,
                supported_languages=["en"],
            )
            self.nlp_mode = "Presidio + spaCy (en_core_web_sm) + Thai Custom Recognizers"
        except Exception:
            # Fallback if spaCy model is unavailable
            self._analyzer = AnalyzerEngine()
            for rec in build_default_custom_recognizers(language="en"):
                self._analyzer.registry.add_recognizer(rec)
            self.nlp_mode = "Presidio Default + Thai Custom Recognizers"

    def add_custom_rule(
        self,
        entity_type: str,
        regex_pattern: str = "",
        score: float = 0.85,
        context_words: Optional[List[str]] = None,
        deny_list: Optional[List[str]] = None,
        description: str = "",
    ) -> Dict[str, Any]:
        """Add a user-defined Presidio PatternRecognizer at runtime."""
        clean_type = entity_type.strip().upper().replace(" ", "_")
        rule_entry = {
            "entity_type": clean_type,
            "regex_pattern": regex_pattern.strip(),
            "score": float(score),
            "context_words": [w.strip() for w in (context_words or []) if w.strip()],
            "deny_list": [w.strip() for w in (deny_list or []) if w.strip()],
            "description": description or f"Custom recognizer for {clean_type}",
        }
        # Replace if same entity_type exists
        self.user_custom_rules = [
            r for r in self.user_custom_rules if r["entity_type"] != clean_type
        ]
        self.user_custom_rules.append(rule_entry)

        rec = create_user_pattern_recognizer(
            entity_type=clean_type,
            regex_pattern=rule_entry["regex_pattern"],
            score=rule_entry["score"],
            context_words=rule_entry["context_words"],
            deny_list=rule_entry["deny_list"],
        )
        if self._analyzer is not None:
            self._analyzer.registry.add_recognizer(rec)
        with self._cache_lock:
            self._analysis_cache.clear()
        return rule_entry

    def remove_custom_rule(self, entity_type: str) -> bool:
        clean_type = entity_type.strip().upper()
        before = len(self.user_custom_rules)
        self.user_custom_rules = [
            r for r in self.user_custom_rules if r["entity_type"] != clean_type
        ]
        if len(self.user_custom_rules) != before:
            with self._cache_lock:
                self._analysis_cache.clear()
            self._init_analyzer()
            return True
        return False

    def get_supported_entities(self) -> List[Dict[str, Any]]:
        """Return full list of built-in + custom entities."""
        items = list(ENTITY_CATALOG)
        known_ids = {item["id"] for item in items}
        for rule in self.user_custom_rules:
            eid = rule["entity_type"]
            if eid not in known_ids:
                items.append(
                    {
                        "id": eid,
                        "label": f"{eid} (Custom Rule)",
                        "category": "Custom PII",
                        "group": "Custom Rules",
                        "description": rule.get("description", "User-defined recognizer"),
                        "default_enabled": True,
                    }
                )
        return items

    @staticmethod
    def _resolve_overlapping_results(
        results: List[RecognizerResult],
    ) -> List[RecognizerResult]:
        """Resolve overlapping entity detections cleanly.

        Prioritizes:
        1. Thai specific recognizers (`TH_*`) over generic `PHONE_NUMBER`/`DATE_TIME`/`PERSON`
           when spans overlap significantly.
        2. Higher confidence score, then longer span length.
        """
        if not results:
            return []

        def _priority_key(r: RecognizerResult) -> Tuple[float, int, int]:
            is_thai_specific = 1 if r.entity_type.startswith("TH_") else 0
            span_len = r.end - r.start
            # Boost priority for TH_* and EMAIL/CREDIT_CARD over generic DATE_TIME
            specificity_bonus = 0.12 if is_thai_specific else 0.0
            if r.entity_type == "DATE_TIME":
                specificity_bonus -= 0.15
            return (round(r.score + specificity_bonus, 4), span_len, is_thai_specific)

        sorted_candidates = sorted(results, key=_priority_key, reverse=True)
        accepted: List[RecognizerResult] = []

        for cand in sorted_candidates:
            if cand.end <= cand.start:
                continue
            overlaps = False
            for acc in accepted:
                # Check if cand and acc overlap
                if max(cand.start, acc.start) < min(cand.end, acc.end):
                    overlaps = True
                    break
            if not overlaps:
                accepted.append(cand)

        # Return sorted by start position ascending
        return sorted(accepted, key=lambda r: (r.start, r.end))

    def analyze_text(
        self,
        text: str,
        entities: Optional[List[str]] = None,
        score_threshold: float = 0.45,
    ) -> List[RecognizerResult]:
        """Analyze text using Presidio AnalyzerEngine with thread-safe caching and parallel chunking."""
        if not text or not text.strip():
            return []

        target_entities = entities
        if not target_entities:
            target_entities = [
                item["id"] for item in self.get_supported_entities() if item.get("default_enabled", True)
            ]

        ent_Key = tuple(sorted(target_entities))
        cache_key = (text, ent_Key, round(float(score_threshold), 3))
        with self._cache_lock:
            cached = self._analysis_cache.get(cache_key)
        if cached is not None:
            return cached

        # For multi-paragraph large text (> 1800 chars), analyze blocks in parallel across CPU workers
        if len(text) > 1800 and "\n" in text:
            lines = text.splitlines(keepends=True)
            chunks: List[Tuple[int, str]] = []
            curr_offset = 0
            curr_buf: List[str] = []
            curr_len = 0
            chunk_start = 0
            for ln in lines:
                curr_buf.append(ln)
                curr_len += len(ln)
                if curr_len >= 900:
                    chunks.append((chunk_start, "".join(curr_buf)))
                    curr_offset += curr_len
                    chunk_start = curr_offset
                    curr_buf = []
                    curr_len = 0
            if curr_buf:
                chunks.append((chunk_start, "".join(curr_buf)))

            def _analyze_chunk(item: Tuple[int, str]) -> List[RecognizerResult]:
                offset, chunk_str = item
                if not chunk_str.strip():
                    return []
                sub_res = self._analyzer.analyze(
                    text=chunk_str,
                    language="en",
                    entities=list(ent_Key),
                    score_threshold=score_threshold,
                )
                shifted: List[RecognizerResult] = []
                for r in sub_res:
                    snip = chunk_str[r.start : r.end]
                    if not snip or not snip.strip():
                        continue
                    # Prevent English spaCy NER (PERSON/LOCATION/NRP) from hallucinating on Thai script
                    if r.entity_type in ("PERSON", "LOCATION", "NRP") and any(
                        "\u0e00" <= ch <= "\u0e7f" for ch in snip
                    ):
                        continue
                    shifted.append(
                        RecognizerResult(
                            entity_type=r.entity_type,
                            start=r.start + offset,
                            end=r.end + offset,
                            score=r.score,
                        )
                    )
                return shifted

            chunk_lists = list(self._executor.map(_analyze_chunk, chunks))
            combined = [r for sub in chunk_lists for r in sub]
            resolved = self._resolve_overlapping_results(combined)
        else:
            raw_results = self._analyzer.analyze(
                text=text,
                language="en",
                entities=list(ent_Key),
                score_threshold=score_threshold,
            )
            filtered: List[RecognizerResult] = []
            for res in raw_results:
                snippet = text[res.start : res.end]
                if not snippet or not snippet.strip():
                    continue
                if res.entity_type in ("PERSON", "LOCATION", "NRP") and any(
                    "\u0e00" <= ch <= "\u0e7f" for ch in snippet
                ):
                    continue
                filtered.append(res)
            resolved = self._resolve_overlapping_results(filtered)

        with self._cache_lock:
            if len(self._analysis_cache) > 8192:
                self._analysis_cache.clear()
            self._analysis_cache[cache_key] = resolved
        return resolved

    def _transform_single_span(
        self,
        span_text: str,
        entity_type: str,
        config: MaskingConfig,
        tokenizer: Optional[ReversibleTokenizer] = None,
    ) -> str:
        """Apply the configured masking/anonymization operator to a single detected PII span."""
        # Check if there is a per-entity override
        override = (config.entity_overrides or {}).get(entity_type, {})
        mode = override.get("mode", config.mode)

        keep_start = int(override.get("keep_start", config.keep_start))
        keep_end = int(override.get("keep_end", config.keep_end))
        mask_start = int(override.get("mask_start", config.mask_start))
        mask_end = int(override.get("mask_end", config.mask_end))
        mask_char = str(override.get("mask_char", config.mask_char) or "*")[0]
        preserve_separators = bool(
            override.get("preserve_separators", config.preserve_separators)
        )
        fixed_mask_len = int(override.get("fixed_mask_len", config.fixed_mask_len))
        smart_short_fallback = bool(
            override.get("smart_short_fallback", config.smart_short_fallback)
        )

        if mode == "keep_prefix_suffix":
            return apply_keep_prefix_suffix(
                text=span_text,
                keep_start=keep_start,
                keep_end=keep_end,
                mask_char=mask_char,
                preserve_separators=preserve_separators,
                fixed_mask_len=fixed_mask_len,
                smart_short_fallback=smart_short_fallback,
            )

        if mode == "mask_prefix_suffix":
            return apply_mask_prefix_suffix(
                text=span_text,
                mask_start=mask_start,
                mask_end=mask_end,
                mask_char=mask_char,
                preserve_separators=preserve_separators,
            )

        if mode == "token":
            if tokenizer is None:
                tokenizer = ReversibleTokenizer()
            return tokenizer.get_token(entity_type, span_text)

        if mode == "replace":
            template = str(override.get("replace_template", config.replace_template) or "<{entity_type}>")
            new_val = template.replace("{entity_type}", entity_type).replace("{text}", span_text)
            # Delegate to Presidio AnonymizerEngine replace operator
            anon_res = self.anonymizer.anonymize(
                text=span_text,
                analyzer_results=[
                    RecognizerResult(entity_type=entity_type, start=0, end=len(span_text), score=1.0)
                ],
                operators={
                    entity_type: OperatorConfig("replace", {"new_value": new_val})
                },
            )
            return anon_res.text

        if mode == "mask":
            chars_to_mask = int(override.get("chars_to_mask", config.chars_to_mask))
            from_end = bool(override.get("from_end", config.from_end))
            anon_res = self.anonymizer.anonymize(
                text=span_text,
                analyzer_results=[
                    RecognizerResult(entity_type=entity_type, start=0, end=len(span_text), score=1.0)
                ],
                operators={
                    entity_type: OperatorConfig(
                        "mask",
                        {
                            "type": "mask",
                            "masking_char": mask_char,
                            "chars_to_mask": max(1, chars_to_mask),
                            "from_end": from_end,
                        },
                    )
                },
            )
            return anon_res.text

        if mode == "redact":
            marker = str(override.get("redact_marker", config.redact_marker) or "")
            if marker:
                return marker
            anon_res = self.anonymizer.anonymize(
                text=span_text,
                analyzer_results=[
                    RecognizerResult(entity_type=entity_type, start=0, end=len(span_text), score=1.0)
                ],
                operators={entity_type: OperatorConfig("redact", {})},
            )
            return anon_res.text

        if mode == "hash":
            hash_type = str(override.get("hash_type", config.hash_type) or "sha256").lower()
            salt = str(override.get("hash_salt", config.hash_salt) or "")
            hash_length = int(override.get("hash_length", config.hash_length))
            if salt:
                payload = f"{salt}:{span_text}".encode("utf-8")
                if hash_type == "md5":
                    digest = hashlib.md5(payload).hexdigest()
                elif hash_type == "sha512":
                    digest = hashlib.sha512(payload).hexdigest()
                else:
                    digest = hashlib.sha256(payload).hexdigest()
            else:
                anon_res = self.anonymizer.anonymize(
                    text=span_text,
                    analyzer_results=[
                        RecognizerResult(
                            entity_type=entity_type, start=0, end=len(span_text), score=1.0
                        )
                    ],
                    operators={
                        entity_type: OperatorConfig("hash", {"hash_type": hash_type})
                    },
                )
                digest = anon_res.text
            if hash_length and hash_length > 0:
                return digest[:hash_length]
            return digest

        # Default fallback: keep_prefix_suffix
        return apply_keep_prefix_suffix(
            text=span_text,
            keep_start=keep_start,
            keep_end=keep_end,
            mask_char=mask_char,
            preserve_separators=preserve_separators,
        )

    def mask_text(
        self,
        text: str,
        config: Optional[MaskingConfig] = None,
        tokenizer: Optional[ReversibleTokenizer] = None,
        disabled_indices: Optional[List[int]] = None,
    ) -> Dict[str, Any]:
        """Analyze and mask PII in plain text.

        Supports interactive toggling of individual detected entities via `disabled_indices`.
        Returns the masked text, detailed entity list (with original & masked values),
        summary counts, and reversible token map.
        """
        cfg = config or MaskingConfig()
        if tokenizer is None:
            tokenizer = ReversibleTokenizer()

        if not text:
            return {
                "original_text": text,
                "masked_text": text,
                "detections": [],
                "entity_counts": {},
                "total_detected": 0,
                "total_masked": 0,
                "token_map": tokenizer.token_to_original,
            }

        detections = self.analyze_text(
            text=text,
            entities=cfg.entities,
            score_threshold=cfg.score_threshold,
        )

        disabled_set = set(disabled_indices or [])
        detailed_detections: List[Dict[str, Any]] = []
        entity_counts: Dict[str, int] = {}

        # Build masked text and track detections in forward order
        output_parts: List[str] = []
        cursor = 0
        total_masked = 0

        for idx, res in enumerate(detections):
            orig_span = text[res.start : res.end]
            is_enabled = idx not in disabled_set

            if is_enabled:
                masked_span = self._transform_single_span(
                    span_text=orig_span,
                    entity_type=res.entity_type,
                    config=cfg,
                    tokenizer=tokenizer,
                )
                total_masked += 1
                entity_counts[res.entity_type] = entity_counts.get(res.entity_type, 0) + 1
            else:
                masked_span = orig_span

            output_parts.append(text[cursor : res.start])
            output_parts.append(masked_span)
            cursor = res.end

            detailed_detections.append(
                {
                    "index": idx,
                    "entity_type": res.entity_type,
                    "start": res.start,
                    "end": res.end,
                    "score": round(float(res.score), 3),
                    "original_text": orig_span,
                    "masked_text": masked_span,
                    "enabled": is_enabled,
                }
            )

        output_parts.append(text[cursor:])
        masked_text = "".join(output_parts)

        return {
            "original_text": text,
            "masked_text": masked_text,
            "detections": detailed_detections,
            "entity_counts": entity_counts,
            "total_detected": len(detailed_detections),
            "total_masked": total_masked,
            "token_map": tokenizer.token_to_original,
        }
