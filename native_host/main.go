package main

import (
	"archive/zip"
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"embed"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/xuri/excelize/v2"
)

//go:embed static/*
var embeddedStatic embed.FS

//go:embed python_src/*
var embeddedPythonSrc embed.FS

type EntityMeta struct {
	ID             string `json:"id"`
	Label          string `json:"label"`
	Category       string `json:"category"`
	Description    string `json:"description"`
	DefaultEnabled bool   `json:"default_enabled"`
}

type CustomRule struct {
	EntityType   string   `json:"entity_type"`
	RegexPattern string   `json:"regex_pattern"`
	Score        float64  `json:"score"`
	ContextWords []string `json:"context_words"`
	DenyList     []string `json:"deny_list"`
	Description  string   `json:"description"`
}

type MaskConfig struct {
	Mode               string                            `json:"mode"`
	KeepStart          int                               `json:"keep_start"`
	KeepEnd            int                               `json:"keep_end"`
	MaskStart          int                               `json:"mask_start"`
	MaskEnd            int                               `json:"mask_end"`
	MaskChar           string                            `json:"mask_char"`
	PreserveSeparators bool                              `json:"preserve_separators"`
	FixedMaskLen       int                               `json:"fixed_mask_len"`
	SmartShortFallback bool                              `json:"smart_short_fallback"`
	CharsToMask        int                               `json:"chars_to_mask"`
	FromEnd            bool                              `json:"from_end"`
	ReplaceTemplate    string                            `json:"replace_template"`
	RedactMarker       string                            `json:"redact_marker"`
	HashType           string                            `json:"hash_type"`
	HashSalt           string                            `json:"hash_salt"`
	HashLength         int                               `json:"hash_length"`
	ScoreThreshold     float64                           `json:"score_threshold"`
	Entities           []string                          `json:"entities"`
	EntityOverrides    map[string]map[string]interface{} `json:"entity_overrides"`
}

type Detection struct {
	Index        int     `json:"index"`
	EntityType   string  `json:"entity_type"`
	Start        int     `json:"start"`
	End          int     `json:"end"`
	Score        float64 `json:"score"`
	OriginalText string  `json:"original_text"`
	MaskedText   string  `json:"masked_text"`
	Enabled      bool    `json:"enabled"`
}

type JobEntry struct {
	RawBytes    []byte
	OutputBytes []byte
	Filename    string
	TokenMap    map[string]string
	CreatedAt   time.Time
}

var (
	jobStoreMu  sync.Mutex
	jobStore    = map[string]*JobEntry{}
	customRules = []CustomRule{}
)

var defaultEntityCatalog = []EntityMeta{
	{"TH_NATIONAL_ID", "Thai National ID (บัตรประชาชน 13 หลัก)", "Thai PII", "13-digit Thai Citizen ID with Modulo-11 checksum verification", true},
	{"TH_PHONE_NUMBER", "Thai Phone Number (เบอร์โทรศัพท์ไทย)", "Thai PII", "Thai mobile (06x/08x/09x, +66) and landline numbers", true},
	{"TH_PERSON_NAME", "Thai Person Name (ชื่อ-นามสกุลไทย)", "Thai PII", "Thai names detected via honorifics (นาย/นาง/นางสาว/คุณ/ดร./นพ.) and labels", true},
	{"TH_BANK_ACCOUNT", "Thai Bank Account (เลขบัญชีธนาคารไทย)", "Thai PII", "10-digit formatted or context-matched Thai bank account numbers", true},
	{"TH_ADDRESS", "Thai Address (ที่อยู่ภาษาไทย)", "Thai PII", "House number, Moo, Soi, Subdistrict, District, Province, Postal Code", true},
	{"TH_LASER_ID", "Thai ID Laser Code (เลขหลังบัตรประชาชน)", "Thai PII", "12-character alphanumeric code on the back of Thai ID cards", true},
	{"TH_LICENSE_PLATE", "Thai License Plate (ทะเบียนรถยนต์ไทย)", "Thai PII", "Thai vehicle registration plates (e.g., 1กข 1234)", true},
	{"PERSON", "Person Name (English / International)", "Global PII", "Full or partial person names", true},
	{"EMAIL_ADDRESS", "Email Address (อีเมล)", "Global PII", "RFC-5322 email addresses", true},
	{"PHONE_NUMBER", "International Phone Number", "Global PII", "Global phone numbers", true},
	{"CREDIT_CARD", "Credit Card Number (บัตรเครดิต)", "Global PII", "Credit cards with Luhn checksum", true},
	{"IBAN_CODE", "IBAN Bank Code", "Global PII", "International Bank Account Number (IBAN)", true},
	{"IP_ADDRESS", "IP Address (IPv4 / IPv6)", "Global PII", "Network IPv4 and IPv6 addresses", true},
	{"URL", "URL / Website Link", "Global PII", "HTTP/HTTPS web addresses", false},
	{"LOCATION", "Location / Address (English)", "Global PII", "Geographic locations and street addresses", true},
	{"DATE_TIME", "Date / Time / Birthdate", "Global PII", "Dates and timestamps", false},
	{"US_SSN", "US Social Security Number (SSN)", "Global PII", "9-digit US Social Security Numbers", true},
	{"US_PASSPORT", "Passport Number", "Global PII", "Passport identifiers", true},
	{"CRYPTO", "Crypto Wallet Address", "Global PII", "Bitcoin/crypto wallet addresses", true},
}

var sampleTexts = map[string]string{
	"thai_english_mixed": "บันทึกข้อมูลลูกค้า (Customer Onboarding Record)\n" +
		"1. ชื่อ-นามสกุล: นายสมชาย ใจดีมาก (Mr. Somchai Jaideemak)\n" +
		"   - เลขบัตรประชาชน: 1-1005-01234-56-7 | เลขหลังบัตร (Laser ID): ME0-1234567-89\n" +
		"   - เบอร์โทรศัพท์มือถือ: 081-234-5678, สำรอง: +66 89 987 6543, เบอร์บ้าน: 02-345-6789\n" +
		"   - อีเมลติดต่อ: somchai.jaidee@company.co.th\n" +
		"   - เลขที่บัญชีธนาคารกสิกรไทย: 123-4-56789-0 | บัตรเครดิต: 4532-0151-1283-0366\n" +
		"   - ที่อยู่จัดส่ง: บ้านเลขที่ 99/12 หมู่ 4 ต.คลองหนึ่ง อ.คลองหลวง จ.ปทุมธานี 12120\n" +
		"   - ทะเบียนรถยนต์: 1กข 4567\n\n" +
		"2. ผู้ติดต่อประสานงาน (Account Manager): นางสาววิภาดา ศรีสุวรรณ และ Dr. Johnathan Smith\n" +
		"   - ติดต่อคุณสมชาย ใจดีมาก ได้ที่เบอร์ 081-234-5678 หรืออีเมล john.smith@globalcorp.com (IP: 192.168.1.105)",
	"thai_support_log": "แจ้งเรื่องร้องเรียน #SR-2026-089\n" +
		"ผู้แจ้ง: พญ.กมลชนก รัตนโชติ (เลขบัตรประชาชน 1-5099-00123-45-2)\n" +
		"รายละเอียด: โอนเงินจากบัญชีไทยพาณิชย์ 456-7-89012-3 ไปยังบัญชีของ นายธนกร วงศ์สวัสดิ์\n" +
		"เบอร์โทรติดต่อกลับ 065-432-1098 ที่อยู่ บ้านเลขที่ 188/5 ถนนนิมมานเหมินท์ ต.สุเทพ อ.เมือง จ.เชียงใหม่ 50200",
	"english_enterprise": "Incident Report #INC-9042\n" +
		"Customer: Alice Wonderland (SSN: 123-45-6789)\n" +
		"Email: alice.wonderland@enterprise.io | Phone: +1-415-555-0199\n" +
		"Payment Card: 4532 0151 1283 0366 | IBAN: DE89370400440532013000\n" +
		"Originating IP: 10.240.18.92 in New York, NY.",
}

// Grapheme clustering for Thai & Unicode
func splitGraphemeClusters(text string) []string {
	if text == "" {
		return nil
	}
	var clusters []string
	for _, r := range text {
		isCombining := unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Mc, r) || unicode.Is(unicode.Me, r) || r == '\u0e33'
		if len(clusters) > 0 && isCombining {
			clusters[len(clusters)-1] += string(r)
		} else {
			clusters = append(clusters, string(r))
		}
	}
	return clusters
}

func isSeparator(c string) bool {
	return strings.ContainsAny(c, " -_./\\@:+(),[]")
}

func applyKeepPrefixSuffix(text string, keepStart, keepEnd int, maskChar string, preserveSep bool, fixedLen int, smartFallback bool) string {
	if text == "" {
		return text
	}
	mc := "*"
	if len([]rune(maskChar)) > 0 {
		mc = string([]rune(maskChar)[0])
	}
	if keepStart < 0 {
		keepStart = 0
	}
	if keepEnd < 0 {
		keepEnd = 0
	}
	clusters := splitGraphemeClusters(text)
	n := len(clusters)
	if n == 0 {
		return text
	}
	effStart := keepStart
	effEnd := keepEnd
	if effStart+effEnd >= n {
		if !smartFallback {
			return text
		}
		if n == 1 {
			return mc
		} else if n == 2 {
			if keepStart > 0 {
				effStart = 1
			} else {
				effStart = 0
			}
			effEnd = 0
		} else if n == 3 {
			if keepStart > 0 {
				effStart = 1
			} else {
				effStart = 0
			}
			if keepEnd > 0 && effStart == 0 {
				effEnd = 1
			} else {
				effEnd = 0
			}
		} else {
			if keepStart > 1 {
				effStart = 1
			}
			if keepEnd > 1 {
				effEnd = 1
			}
		}
	}
	prefix := strings.Join(clusters[:effStart], "")
	suffix := ""
	endIdx := n
	if effEnd > 0 {
		endIdx = n - effEnd
		suffix = strings.Join(clusters[endIdx:], "")
	}
	midClusters := clusters[effStart:endIdx]
	var midMasked strings.Builder
	if fixedLen > 0 {
		midMasked.WriteString(strings.Repeat(mc, fixedLen))
	} else if preserveSep {
		for _, c := range midClusters {
			if isSeparator(c) {
				midMasked.WriteString(c)
			} else {
				midMasked.WriteString(mc)
			}
		}
	} else {
		midMasked.WriteString(strings.Repeat(mc, len(midClusters)))
	}
	return prefix + midMasked.String() + suffix
}

func applyMaskPrefixSuffix(text string, maskStart, maskEnd int, maskChar string, preserveSep bool) string {
	if text == "" {
		return text
	}
	mc := "*"
	if len([]rune(maskChar)) > 0 {
		mc = string([]rune(maskChar)[0])
	}
	clusters := splitGraphemeClusters(text)
	n := len(clusters)
	if maskStart+maskEnd >= n {
		return strings.Repeat(mc, n)
	}
	endIdx := n
	if maskEnd > 0 {
		endIdx = n - maskEnd
	}
	front := strings.Repeat(mc, maskStart)
	mid := strings.Join(clusters[maskStart:endIdx], "")
	back := strings.Repeat(mc, maskEnd)
	return front + mid + back
}

func validateThaiIDChecksum(raw string) bool {
	var digits []int
	for _, r := range raw {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) != 13 || digits[0] == 0 {
		return false
	}
	sum := 0
	for i := 0; i < 12; i++ {
		sum += digits[i] * (13 - i)
	}
	check := (11 - (sum % 11)) % 10
	return check == digits[12]
}

type rawMatch struct {
	EntityType string
	ByteStart  int
	ByteEnd    int
	RuneStart  int
	RuneEnd    int
	Score      float64
}

var (
	reThIDFormatted = regexp.MustCompile(`[1-8][-\s]\d{4}[-\s]\d{5}[-\s]\d{2}[-\s]\d`)
	reThIDPlain     = regexp.MustCompile(`[1-8]\d{12}`)
	reThMobile      = regexp.MustCompile(`(?:\+66[-\s]?[689]\d|0[689]\d)[-\s]?\d{3}[-\s]?\d{4}`)
	reThLandline    = regexp.MustCompile(`02[-\s]?\d{3}[-\s]?\d{4}|0[3457]\d[-\s]?\d{3}[-\s]?\d{3}`)
	reThNameHonor   = regexp.MustCompile(`(นางสาว|น\.ส\.|นาย|นาง|ด\.ช\.|ด\.ญ\.|เด็กชาย|เด็กหญิง|คุณ|ผศ\.ดร\.|รศ\.ดร\.|ศ\.ดร\.|ดร\.|ผศ\.|รศ\.|ศ\.|นพ\.|พญ\.|ทพ\.|ทพญ\.|ภก\.|ภญ\.|พล\.ต\.อ\.|พล\.อ\.|พ\.ต\.อ\.|ร\.ต\.อ\.)\s*([\p{Thai}]{2,35}(?:\s+[\p{Thai}]{2,35})?)`)
	reThBank        = regexp.MustCompile(`\d{3}-\d-\d{5}-\d`)
	reThAddress     = regexp.MustCompile(`(?:บ้านเลขที่|เลขที่)\s*\d+(?:/\d+)?(?:\s*(?:หมู่(?:ที่)?|ม\.)\s*\d+)?(?:\s*(?:ซอย|ซ\.|ถนน|ถ\.|ต\.|ตำบล|แขวง|อ\.|อำเภอ|เขต|จ\.|จังหวัด|กทม\.?|กรุงเทพ(?:มหานคร)?)[^\n,;]{0,80})?(?:\s*[1-9]\d{4})?`)
	reThLaser       = regexp.MustCompile(`[A-Z]{2}\d-?\d{7}-?\d{2}`)
	reThPlate       = regexp.MustCompile(`(?:[1-9]\s*)?[ก-ฮ]{2,3}[-\s]\d{1,4}`)
	reEmail         = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	reCreditCard    = regexp.MustCompile(`(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}`)
	reIBAN          = regexp.MustCompile(`[A-Z]{2}\d{2}[A-Z0-9]{11,30}`)
	reIPv4          = regexp.MustCompile(`(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}`)
	reURL           = regexp.MustCompile(`https?://[^\s<>"]+`)
	reUSSSN         = regexp.MustCompile(`\d{3}-\d{2}-\d{4}`)
	reIntlPhone     = regexp.MustCompile(`\+\d{1,3}[-\s]?\d{2,4}[-\s]?\d{3,4}[-\s]?\d{3,4}`)
	reEngPerson     = regexp.MustCompile(`(?:Mr\.|Mrs\.|Ms\.|Dr\.|Prof\.|Customer:|Reporter:)?\s*([A-Z][a-z]{2,20}(?:\s+[A-Z][a-z]{2,20}){1,2})`)
)

var stopThaiSurnameWords = map[string]bool{
	"โทร": true, "เบอร์": true, "เบอร์โทร": true, "ติดต่อ": true,
	"ที่อยู่": true, "เลขที่": true, "บ้านเลขที่": true, "อีเมล": true,
	"บัตร": true, "เลขบัตร": true, "บัญชี": true, "ธนาคาร": true,
}

func byteOffsetsToRuneOffsets(text string) []int {
	// maps byte index -> rune index
	mapping := make([]int, len(text)+1)
	runeIdx := 0
	for byteIdx := range text {
		mapping[byteIdx] = runeIdx
		runeIdx++
	}
	mapping[len(text)] = runeIdx
	return mapping
}

func analyzeTextNative(text string, enabledEntities map[string]bool, threshold float64) []rawMatch {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	b2r := byteOffsetsToRuneOffsets(text)
	var matches []rawMatch

	addRegexMatches := func(etype string, re *regexp.Regexp, baseScore float64, validator func(string) (bool, float64)) {
		if !enabledEntities[etype] {
			return
		}
		for _, loc := range re.FindAllStringIndex(text, -1) {
			bStart, bEnd := loc[0], loc[1]
			// Check boundary digits if numeric
			snippet := text[bStart:bEnd]
			sc := baseScore
			if validator != nil {
				ok, newSc := validator(snippet)
				if !ok {
					continue
				}
				sc = newSc
			}
			if sc >= threshold {
				matches = append(matches, rawMatch{
					EntityType: etype,
					ByteStart:  bStart,
					ByteEnd:    bEnd,
					RuneStart:  b2r[bStart],
					RuneEnd:    b2r[bEnd],
					Score:      sc,
				})
			}
		}
	}

	// Thai National ID
	addRegexMatches("TH_NATIONAL_ID", reThIDFormatted, 0.85, func(s string) (bool, float64) {
		if validateThaiIDChecksum(s) {
			return true, 1.0
		}
		return true, 0.75
	})
	addRegexMatches("TH_NATIONAL_ID", reThIDPlain, 0.65, func(s string) (bool, float64) {
		if validateThaiIDChecksum(s) {
			return true, 0.98
		}
		return true, 0.65
	})

	// Thai Phone
	addRegexMatches("TH_PHONE_NUMBER", reThMobile, 0.90, nil)
	addRegexMatches("TH_PHONE_NUMBER", reThLandline, 0.82, nil)

	// Thai Person Name (extract group 2 so honorific is kept clean)
	if enabledEntities["TH_PERSON_NAME"] {
		for _, sub := range reThNameHonor.FindAllStringSubmatchIndex(text, -1) {
			if len(sub) >= 6 && sub[4] >= 0 && sub[5] > sub[4] {
				nameStart, nameEnd := sub[4], sub[5]
				nameStr := text[nameStart:nameEnd]
				parts := strings.Fields(nameStr)
				if len(parts) == 2 && stopThaiSurnameWords[parts[1]] {
					nameEnd = nameStart + len(parts[0])
				}
				matches = append(matches, rawMatch{
					EntityType: "TH_PERSON_NAME",
					ByteStart:  nameStart,
					ByteEnd:    nameEnd,
					RuneStart:  b2r[nameStart],
					RuneEnd:    b2r[nameEnd],
					Score:      0.90,
				})
			}
		}
	}

	addRegexMatches("TH_BANK_ACCOUNT", reThBank, 0.88, nil)
	addRegexMatches("TH_ADDRESS", reThAddress, 0.86, nil)
	addRegexMatches("TH_LASER_ID", reThLaser, 0.88, nil)
	addRegexMatches("TH_LICENSE_PLATE", reThPlate, 0.80, nil)
	addRegexMatches("EMAIL_ADDRESS", reEmail, 0.98, nil)
	addRegexMatches("CREDIT_CARD", reCreditCard, 0.95, nil)
	addRegexMatches("IBAN_CODE", reIBAN, 0.92, nil)
	addRegexMatches("IP_ADDRESS", reIPv4, 0.90, nil)
	addRegexMatches("URL", reURL, 0.85, nil)
	addRegexMatches("US_SSN", reUSSSN, 0.88, nil)
	addRegexMatches("PHONE_NUMBER", reIntlPhone, 0.85, nil)

	// English Person Name
	if enabledEntities["PERSON"] {
		stopEng := map[string]bool{
			"Customer Onboarding": true, "Customer Onboarding Record": true,
			"Account Manager": true, "Incident Report": true,
			"Silom Road": true, "Bang Rak": true, "New York": true,
			"Laser ID": true, "Payment Card": true, "Originating IP": true,
		}
		for _, sub := range reEngPerson.FindAllStringSubmatchIndex(text, -1) {
			if len(sub) >= 4 && sub[2] >= 0 && sub[3] > sub[2] {
				bStart, bEnd := sub[2], sub[3]
				cand := strings.TrimSpace(text[bStart:bEnd])
				if stopEng[cand] {
					continue
				}
				matches = append(matches, rawMatch{
					EntityType: "PERSON",
					ByteStart:  bStart,
					ByteEnd:    bEnd,
					RuneStart:  b2r[bStart],
					RuneEnd:    b2r[bEnd],
					Score:      0.85,
				})
			}
		}
	}

	// Custom Rules
	for _, rule := range customRules {
		if !enabledEntities[rule.EntityType] {
			continue
		}
		if rule.RegexPattern != "" {
			if cre, err := regexp.Compile(rule.RegexPattern); err == nil {
				addRegexMatches(rule.EntityType, cre, rule.Score, nil)
			}
		}
		for _, dw := range rule.DenyList {
			dw = strings.TrimSpace(dw)
			if dw == "" {
				continue
			}
			idx := 0
			for {
				pos := strings.Index(text[idx:], dw)
				if pos == -1 {
					break
				}
				bStart := idx + pos
				bEnd := bStart + len(dw)
				matches = append(matches, rawMatch{
					EntityType: rule.EntityType,
					ByteStart:  bStart,
					ByteEnd:    bEnd,
					RuneStart:  b2r[bStart],
					RuneEnd:    b2r[bEnd],
					Score:      rule.Score,
				})
				idx = bEnd
			}
		}
	}

	// Resolve overlaps: prioritize higher score & longer span
	sort.SliceStable(matches, func(i, j int) bool {
		si := matches[i].Score
		if strings.HasPrefix(matches[i].EntityType, "TH_") {
			si += 0.1
		}
		sj := matches[j].Score
		if strings.HasPrefix(matches[j].EntityType, "TH_") {
			sj += 0.1
		}
		if math.Abs(si-sj) > 0.001 {
			return si > sj
		}
		return (matches[i].RuneEnd - matches[i].RuneStart) > (matches[j].RuneEnd - matches[j].RuneStart)
	})

	var accepted []rawMatch
	for _, m := range matches {
		overlaps := false
		for _, a := range accepted {
			if maxInt(m.ByteStart, a.ByteStart) < minInt(m.ByteEnd, a.ByteEnd) {
				overlaps = true
				break
			}
		}
		if !overlaps {
			accepted = append(accepted, m)
		}
	}

	sort.Slice(accepted, func(i, j int) bool {
		return accepted[i].ByteStart < accepted[j].ByteStart
	})
	return accepted
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type TokenizerState struct {
	mu              sync.Mutex
	TokenToOriginal map[string]string
	lookup          map[string]string
	counters        map[string]int
}

func NewTokenizerState() *TokenizerState {
	return &TokenizerState{
		TokenToOriginal: map[string]string{},
		lookup:          map[string]string{},
		counters:        map[string]int{},
	}
}

func (t *TokenizerState) GetToken(entityType, orig string) string {
	key := entityType + "::" + strings.TrimSpace(orig)
	t.mu.Lock()
	defer t.mu.Unlock()
	if tok, ok := t.lookup[key]; ok {
		return tok
	}
	next := t.counters[entityType] + 1
	t.counters[entityType] = next
	tok := fmt.Sprintf("[%s_%d]", entityType, next)
	t.lookup[key] = tok
	t.TokenToOriginal[tok] = orig
	return tok
}

func transformSpan(spanText, entityType string, cfg MaskConfig, tok *TokenizerState) string {
	mode := cfg.Mode
	if mode == "" {
		mode = "keep_prefix_suffix"
	}
	mc := cfg.MaskChar
	if mc == "" {
		mc = "*"
	}
	switch mode {
	case "keep_prefix_suffix":
		return applyKeepPrefixSuffix(spanText, cfg.KeepStart, cfg.KeepEnd, mc, cfg.PreserveSeparators, cfg.FixedMaskLen, true)
	case "mask_prefix_suffix":
		return applyMaskPrefixSuffix(spanText, cfg.MaskStart, cfg.MaskEnd, mc, cfg.PreserveSeparators)
	case "replace":
		tpl := cfg.ReplaceTemplate
		if tpl == "" {
			tpl = "<{entity_type}>"
		}
		return strings.ReplaceAll(tpl, "{entity_type}", entityType)
	case "token":
		return tok.GetToken(entityType, spanText)
	case "redact":
		return cfg.RedactMarker
	case "hash":
		payload := spanText
		if cfg.HashSalt != "" {
			payload = cfg.HashSalt + ":" + spanText
		}
		var hexDigest string
		switch strings.ToLower(cfg.HashType) {
		case "md5":
			sum := md5.Sum([]byte(payload))
			hexDigest = hex.EncodeToString(sum[:])
		case "sha512":
			sum := sha512.Sum512([]byte(payload))
			hexDigest = hex.EncodeToString(sum[:])
		default:
			sum := sha256.Sum256([]byte(payload))
			hexDigest = hex.EncodeToString(sum[:])
		}
		if cfg.HashLength > 0 && cfg.HashLength < len(hexDigest) {
			return hexDigest[:cfg.HashLength]
		}
		return hexDigest
	case "mask":
		clusters := splitGraphemeClusters(spanText)
		n := len(clusters)
		c2m := cfg.CharsToMask
		if c2m <= 0 {
			c2m = 6
		}
		if c2m >= n {
			return strings.Repeat(string([]rune(mc)[0]), n)
		}
		if cfg.FromEnd {
			return strings.Join(clusters[:n-c2m], "") + strings.Repeat(string([]rune(mc)[0]), c2m)
		}
		return strings.Repeat(string([]rune(mc)[0]), c2m) + strings.Join(clusters[c2m:], "")
	default:
		return applyKeepPrefixSuffix(spanText, cfg.KeepStart, cfg.KeepEnd, mc, cfg.PreserveSeparators, cfg.FixedMaskLen, true)
	}
}

func maskTextNative(text string, cfg MaskConfig, disabledIndices []int, tok *TokenizerState) map[string]interface{} {
	if tok == nil {
		tok = NewTokenizerState()
	}
	enabledSet := map[string]bool{}
	if len(cfg.Entities) == 0 {
		for _, e := range defaultEntityCatalog {
			if e.DefaultEnabled {
				enabledSet[e.ID] = true
			}
		}
		for _, r := range customRules {
			enabledSet[r.EntityType] = true
		}
	} else {
		for _, id := range cfg.Entities {
			enabledSet[id] = true
		}
	}
	threshold := cfg.ScoreThreshold
	if threshold <= 0 {
		threshold = 0.45
	}

	rawMatches := analyzeTextNative(text, enabledSet, threshold)
	disabledMap := map[int]bool{}
	for _, idx := range disabledIndices {
		disabledMap[idx] = true
	}

	var out strings.Builder
	cursor := 0
	var detections []Detection
	entityCounts := map[string]int{}
	totalMasked := 0

	for idx, m := range rawMatches {
		origSpan := text[m.ByteStart:m.ByteEnd]
		enabled := !disabledMap[idx]
		maskedSpan := origSpan
		if enabled {
			maskedSpan = transformSpan(origSpan, m.EntityType, cfg, tok)
			totalMasked++
			entityCounts[m.EntityType]++
		}
		out.WriteString(text[cursor:m.ByteStart])
		out.WriteString(maskedSpan)
		cursor = m.ByteEnd

		detections = append(detections, Detection{
			Index:        idx,
			EntityType:   m.EntityType,
			Start:        m.RuneStart,
			End:          m.RuneEnd,
			Score:        m.Score,
			OriginalText: origSpan,
			MaskedText:   maskedSpan,
			Enabled:      enabled,
		})
	}
	out.WriteString(text[cursor:])
	if detections == nil {
		detections = []Detection{}
	}

	return map[string]interface{}{
		"original_text":  text,
		"masked_text":    out.String(),
		"detections":     detections,
		"entity_counts":  entityCounts,
		"total_detected": len(detections),
		"total_masked":   totalMasked,
		"token_map":      tok.TokenToOriginal,
	}
}

func restoreTextNative(text string, tokenMap map[string]string) (string, int) {
	if text == "" || len(tokenMap) == 0 {
		return text, 0
	}
	keys := make([]string, 0, len(tokenMap))
	for k := range tokenMap {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return len(keys[i]) > len(keys[j])
	})
	restored := text
	count := 0
	for _, k := range keys {
		occ := strings.Count(restored, k)
		if occ > 0 {
			restored = strings.ReplaceAll(restored, k, tokenMap[k])
			count += occ
		}
	}
	return restored, count
}

func generateSampleExcelBytesNative() ([]byte, error) {
	f := excelize.NewFile()
	s1 := "Customers_TH_EN"
	f.SetSheetName("Sheet1", s1)

	headers1 := []string{
		"Customer_ID",
		"Full_Name (ชื่อ-นามสกุล)",
		"National_ID (บัตรประชาชน)",
		"Phone (เบอร์โทรศัพท์)",
		"Email (อีเมล)",
		"Bank_Account (เลขบัญชี)",
		"Address (ที่อยู่จัดส่ง)",
		"Notes (หมายเหตุ)",
	}
	for i, h := range headers1 {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		f.SetCellValue(s1, cell, h)
	}
	rows1 := [][]string{
		{"CUST-001", "นายสมชาย ใจดีมาก", "1-1005-01234-56-7", "081-234-5678", "somchai.jaidee@company.co.th", "123-4-56789-0", "บ้านเลขที่ 99/12 หมู่ 4 ต.คลองหนึ่ง อ.คลองหลวง จ.ปทุมธานี 12120", "ลูกค้า VIP ติดต่อคุณสมชาย โทร 081-234-5678 หรือหลังบัตร ME0-1234567-89"},
		{"CUST-002", "นางสาววิภาดา ศรีสุวรรณ", "3-1012-00456-78-1", "092-876-5432", "wipada.sri@gmail.com", "456-7-89012-3", "เลขที่ 45 ซอยสุขุมวิท 24 แขวงคลองตัน เขตคลองเตย กรุงเทพมหานคร 10110", "ทะเบียนรถ 1กข 4567 ชำระผ่านบัตรเครดิต 4532-0151-1283-0366"},
		{"CUST-003", "Mr. Johnathan Edward Smith", "1100501234567", "+66 89 111 2233", "john.smith@globalcorp.com", "789-0-12345-6", "120 Silom Road, Bang Rak, Bangkok 10500", "Contact John Smith at john.smith@globalcorp.com or IP 192.168.10.45"},
		{"CUST-004", "พญ.กมลชนก รัตนโชติ", "1-5099-00123-45-2", "065-432-1098", "dr.kamonchanok@hospital.or.th", "901-2-34567-8", "บ้านเลขที่ 188/5 ถนนนิมมานเหมินท์ ต.สุเทพ อ.เมือง จ.เชียงใหม่ 50200", "ผู้ติดต่อสำรอง นายสมชาย ใจดีมาก โทร 02-345-6789"},
	}
	for rIdx, row := range rows1 {
		for cIdx, val := range row {
			cell, _ := excelize.CoordinatesToCellName(cIdx+1, rIdx+2)
			f.SetCellValue(s1, cell, val)
		}
	}

	s2 := "HR_Support_Tickets"
	f.NewSheet(s2)
	headers2 := []string{"Ticket_ID", "Reporter", "Incident_Summary", "Server_IP"}
	for i, h := range headers2 {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		f.SetCellValue(s2, cell, h)
	}
	rows2 := [][]string{
		{"TCK-101", "คุณธนกร วงศ์สวัสดิ์", "ลูกค้าแจ้งเปลี่ยนเบอร์จาก 081-234-5678 เป็น 099-112-3344 และอีเมล thanakorn.w@example.com", "10.24.88.19"},
		{"TCK-102", "Alice Wonderland", "Refund requested to KBANK account 123-4-56789-0 for Alice Wonderland (SSN 123-45-6789)", "172.16.0.104"},
	}
	for rIdx, row := range rows2 {
		for cIdx, val := range row {
			cell, _ := excelize.CoordinatesToCellName(cIdx+1, rIdx+2)
			f.SetCellValue(s2, cell, val)
		}
	}

	buf, err := f.WriteToBuffer()
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func inspectTabularNative(fileBytes []byte, filename string) (map[string]interface{}, error) {
	lower := strings.ToLower(filename)
	if strings.HasSuffix(lower, ".csv") || strings.HasSuffix(lower, ".tsv") {
		r := csv.NewReader(bytes.NewReader(fileBytes))
		if strings.HasSuffix(lower, ".tsv") {
			r.Comma = '\t'
		}
		records, err := r.ReadAll()
		if err != nil && len(records) == 0 {
			return nil, err
		}
		var headers []string
		var preview []map[string]string
		if len(records) > 0 {
			headers = records[0]
			for i := 1; i < len(records) && i <= 10; i++ {
				rowMap := map[string]string{}
				for cIdx, h := range headers {
					if cIdx < len(records[i]) {
						rowMap[h] = records[i][cIdx]
					} else {
						rowMap[h] = ""
					}
				}
				preview = append(preview, rowMap)
			}
		}
		rowCount := 0
		if len(records) > 1 {
			rowCount = len(records) - 1
		}
		return map[string]interface{}{
			"filename":  filename,
			"file_type": "csv",
			"sheets": []map[string]interface{}{
				{
					"name":         "CSV_Data",
					"columns":      headers,
					"row_count":    rowCount,
					"preview_rows": preview,
				},
			},
		}, nil
	}

	f, err := excelize.OpenReader(bytes.NewReader(fileBytes))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var sheets []map[string]interface{}
	for _, sname := range f.GetSheetList() {
		rows, _ := f.GetRows(sname)
		var headers []string
		var preview []map[string]string
		if len(rows) > 0 {
			for idx, h := range rows[0] {
				if strings.TrimSpace(h) == "" {
					headers = append(headers, fmt.Sprintf("Column_%d", idx+1))
				} else {
					headers = append(headers, strings.TrimSpace(h))
				}
			}
			for rIdx := 1; rIdx < len(rows) && rIdx <= 10; rIdx++ {
				rowMap := map[string]string{}
				for cIdx, h := range headers {
					if cIdx < len(rows[rIdx]) {
						rowMap[h] = rows[rIdx][cIdx]
					} else {
						rowMap[h] = ""
					}
				}
				preview = append(preview, rowMap)
			}
		}
		rowCount := 0
		if len(rows) > 1 {
			rowCount = len(rows) - 1
		}
		sheets = append(sheets, map[string]interface{}{
			"name":         sname,
			"columns":      headers,
			"row_count":    rowCount,
			"preview_rows": preview,
		})
	}
	return map[string]interface{}{
		"filename":  filename,
		"file_type": "xlsx",
		"sheets":    sheets,
	}, nil
}

func maskTabularNative(
	fileBytes []byte,
	filename string,
	cfg MaskConfig,
	selectedSheets []string,
	selectedCols map[string][]string,
	forceMaskSelected bool,
	includeAuditSheet bool,
) (map[string]interface{}, error) {
	tok := NewTokenizerState()
	totalScanned := 0
	totalMasked := 0
	entityCounts := map[string]int{}
	sheetPreviews := map[string][]map[string]interface{}{}

	lower := strings.ToLower(filename)
	if strings.HasSuffix(lower, ".csv") || strings.HasSuffix(lower, ".tsv") {
		r := csv.NewReader(bytes.NewReader(fileBytes))
		if strings.HasSuffix(lower, ".tsv") {
			r.Comma = '\t'
		}
		records, err := r.ReadAll()
		if err != nil && len(records) == 0 {
			return nil, err
		}
		if len(records) == 0 {
			return map[string]interface{}{
				"output_bytes":        fileBytes,
				"filename":            "masked_" + filename,
				"total_cells_scanned": 0,
				"total_cells_masked":  0,
				"entity_counts":       entityCounts,
				"sheet_previews":      sheetPreviews,
				"token_map":           tok.TokenToOriginal,
			}, nil
		}
		headers := records[0]
		allowedCols := map[string]bool{}
		for _, c := range selectedCols["CSV_Data"] {
			allowedCols[c] = true
		}
		var previewList []map[string]interface{}
		for rIdx := 1; rIdx < len(records); rIdx++ {
			rowBefore := map[string]string{}
			rowAfter := map[string]string{}
			var changedCols []string
			for cIdx := 0; cIdx < len(records[rIdx]); cIdx++ {
				colName := fmt.Sprintf("Col_%d", cIdx+1)
				if cIdx < len(headers) {
					colName = headers[cIdx]
				}
				val := records[rIdx][cIdx]
				rowBefore[colName] = val
				shouldScan := len(allowedCols) == 0 || allowedCols[colName]
				if shouldScan && strings.TrimSpace(val) != "" {
					totalScanned++
					res := maskTextNative(val, cfg, nil, tok)
					tm := res["total_masked"].(int)
					maskedStr := res["masked_text"].(string)
					if tm == 0 && forceMaskSelected && allowedCols[colName] {
						maskedStr = transformSpan(val, "PII_DATA", cfg, tok)
						tm = 1
					}
					records[rIdx][cIdx] = maskedStr
					rowAfter[colName] = maskedStr
					if tm > 0 && maskedStr != val {
						totalMasked++
						changedCols = append(changedCols, colName)
					}
				} else {
					rowAfter[colName] = val
				}
			}
			if len(previewList) < 25 {
				previewList = append(previewList, map[string]interface{}{
					"row_index":       rIdx,
					"before":          rowBefore,
					"after":           rowAfter,
					"changed_columns": changedCols,
				})
			}
		}
		sheetPreviews["CSV_Data"] = previewList
		var outBuf bytes.Buffer
		w := csv.NewWriter(&outBuf)
		if strings.HasSuffix(lower, ".tsv") {
			w.Comma = '\t'
		}
		w.WriteAll(records)
		w.Flush()
		return map[string]interface{}{
			"output_bytes":        outBuf.Bytes(),
			"filename":            "masked_" + filename,
			"total_cells_scanned": totalScanned,
			"total_cells_masked":  totalMasked,
			"entity_counts":       entityCounts,
			"sheet_previews":      sheetPreviews,
			"token_map":           tok.TokenToOriginal,
		}, nil
	}

	f, err := excelize.OpenReader(bytes.NewReader(fileBytes))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sheetSet := map[string]bool{}
	for _, s := range selectedSheets {
		sheetSet[s] = true
	}

	// Collect unique cells for parallel multi-core worker pool
	type cellKey struct {
		val        string
		colName    string
		isExplicit bool
	}
	type cellResult struct {
		maskedStr string
		modified  bool
	}
	uniqueMap := map[cellKey]bool{}
	for _, sname := range f.GetSheetList() {
		if len(sheetSet) > 0 && !sheetSet[sname] {
			continue
		}
		rows, _ := f.GetRows(sname)
		if len(rows) < 2 {
			continue
		}
		var headers []string
		for idx, h := range rows[0] {
			if strings.TrimSpace(h) == "" {
				headers = append(headers, fmt.Sprintf("Column_%d", idx+1))
			} else {
				headers = append(headers, strings.TrimSpace(h))
			}
		}
		allowedCols := map[string]bool{}
		for _, c := range selectedCols[sname] {
			allowedCols[c] = true
		}
		for rIdx := 1; rIdx < len(rows); rIdx++ {
			for cIdx := 0; cIdx < len(headers) && cIdx < len(rows[rIdx]); cIdx++ {
				colName := headers[cIdx]
				val := rows[rIdx][cIdx]
				shouldScan := len(allowedCols) == 0 || allowedCols[colName]
				if shouldScan && strings.TrimSpace(val) != "" && !strings.HasPrefix(val, "=") {
					uniqueMap[cellKey{val: val, colName: colName, isExplicit: allowedCols[colName]}] = true
				}
			}
		}
	}

	keysList := make([]cellKey, 0, len(uniqueMap))
	for k := range uniqueMap {
		keysList = append(keysList, k)
	}
	resultsSlice := make([]cellResult, len(keysList))
	numWorkers := runtime.NumCPU()
	if numWorkers < 2 {
		numWorkers = 2
	}
	var wg sync.WaitGroup
	jobCh := make(chan int, len(keysList))
	for i := range keysList {
		jobCh <- i
	}
	close(jobCh)

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobCh {
				k := keysList[idx]
				res := maskTextNative(k.val, cfg, nil, tok)
				tm := res["total_masked"].(int)
				maskedStr := res["masked_text"].(string)
				if tm == 0 && forceMaskSelected && k.isExplicit {
					maskedStr = transformSpan(k.val, "PII_DATA", cfg, tok)
					tm = 1
				}
				resultsSlice[idx] = cellResult{
					maskedStr: maskedStr,
					modified:  tm > 0 && maskedStr != k.val,
				}
			}
		}()
	}
	wg.Wait()

	cacheResults := make(map[cellKey]cellResult, len(keysList))
	for i, k := range keysList {
		cacheResults[k] = resultsSlice[i]
	}

	for _, sname := range f.GetSheetList() {
		if len(sheetSet) > 0 && !sheetSet[sname] {
			continue
		}
		rows, _ := f.GetRows(sname)
		if len(rows) < 2 {
			continue
		}
		var headers []string
		for idx, h := range rows[0] {
			if strings.TrimSpace(h) == "" {
				headers = append(headers, fmt.Sprintf("Column_%d", idx+1))
			} else {
				headers = append(headers, strings.TrimSpace(h))
			}
		}
		allowedCols := map[string]bool{}
		for _, c := range selectedCols[sname] {
			allowedCols[c] = true
		}

		var previewList []map[string]interface{}
		for rIdx := 1; rIdx < len(rows); rIdx++ {
			rowBefore := map[string]string{}
			rowAfter := map[string]string{}
			var changedCols []string
			for cIdx := 0; cIdx < len(headers); cIdx++ {
				colName := headers[cIdx]
				val := ""
				if cIdx < len(rows[rIdx]) {
					val = rows[rIdx][cIdx]
				}
				rowBefore[colName] = val
				shouldScan := len(allowedCols) == 0 || allowedCols[colName]
				if shouldScan && strings.TrimSpace(val) != "" && !strings.HasPrefix(val, "=") {
					totalScanned++
					cr := cacheResults[cellKey{val: val, colName: colName, isExplicit: allowedCols[colName]}]
					if cr.modified {
						cellName, _ := excelize.CoordinatesToCellName(cIdx+1, rIdx+1)
						f.SetCellValue(sname, cellName, cr.maskedStr)
						totalMasked++
						changedCols = append(changedCols, colName)
						rowAfter[colName] = cr.maskedStr
					} else {
						rowAfter[colName] = val
					}
				} else {
					rowAfter[colName] = val
				}
			}
			if len(previewList) < 25 {
				previewList = append(previewList, map[string]interface{}{
					"row_index":       rIdx,
					"before":          rowBefore,
					"after":           rowAfter,
					"changed_columns": changedCols,
				})
			}
		}
		sheetPreviews[sname] = previewList
	}

	if includeAuditSheet && len(tok.TokenToOriginal) > 0 {
		vault := "_PII_Token_Vault"
		f.NewSheet(vault)
		f.SetCellValue(vault, "A1", "Token")
		f.SetCellValue(vault, "B1", "Original_PII_Value")
		r := 2
		for k, v := range tok.TokenToOriginal {
			c1, _ := excelize.CoordinatesToCellName(1, r)
			c2, _ := excelize.CoordinatesToCellName(2, r)
			f.SetCellValue(vault, c1, k)
			f.SetCellValue(vault, c2, v)
			r++
		}
	}

	buf, err := f.WriteToBuffer()
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"output_bytes":        buf.Bytes(),
		"filename":            "masked_" + filename,
		"total_cells_scanned": totalScanned,
		"total_cells_masked":  totalMasked,
		"entity_counts":       entityCounts,
		"sheet_previews":      sheetPreviews,
		"token_map":           tok.TokenToOriginal,
	}, nil
}

func restoreTabularNative(fileBytes []byte, filename string, tokenMap map[string]string) ([]byte, int, error) {
	lower := strings.ToLower(filename)
	if strings.HasSuffix(lower, ".csv") || strings.HasSuffix(lower, ".tsv") {
		restored, count := restoreTextNative(string(fileBytes), tokenMap)
		return []byte(restored), count, nil
	}
	f, err := excelize.OpenReader(bytes.NewReader(fileBytes))
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	merged := map[string]string{}
	for k, v := range tokenMap {
		merged[k] = v
	}
	for _, sname := range f.GetSheetList() {
		if sname == "_PII_Token_Vault" {
			rows, _ := f.GetRows(sname)
			for i := 1; i < len(rows); i++ {
				if len(rows[i]) >= 2 {
					merged[strings.TrimSpace(rows[i][0])] = rows[i][1]
				}
			}
		}
	}

	totalRestored := 0
	for _, sname := range f.GetSheetList() {
		if sname == "_PII_Token_Vault" {
			continue
		}
		rows, _ := f.GetRows(sname)
		for rIdx, row := range rows {
			for cIdx, val := range row {
				if val != "" {
					newVal, cnt := restoreTextNative(val, merged)
					if cnt > 0 {
						cellName, _ := excelize.CoordinatesToCellName(cIdx+1, rIdx+1)
						f.SetCellValue(sname, cellName, newVal)
						totalRestored += cnt
					}
				}
			}
		}
	}
	buf, err := f.WriteToBuffer()
	if err != nil {
		return nil, 0, err
	}
	return buf.Bytes(), totalRestored, nil
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func buildHTTPMux() http.Handler {
	mux := http.NewServeMux()

	staticSub, _ := fs.Sub(embeddedStatic, "static")
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		data, err := embeddedStatic.ReadFile("static/index.html")
		if err != nil {
			http.Error(w, "UI missing", 500)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(data)
	})

	mux.HandleFunc("/api/info", func(w http.ResponseWriter, r *http.Request) {
		allEntities := make([]EntityMeta, len(defaultEntityCatalog))
		copy(allEntities, defaultEntityCatalog)
		for _, cr := range customRules {
			allEntities = append(allEntities, EntityMeta{
				ID:             cr.EntityType,
				Label:          cr.EntityType + " (Custom Rule)",
				Category:       "Custom PII",
				Description:    cr.Description,
				DefaultEnabled: true,
			})
		}
		writeJSON(w, 200, map[string]interface{}{
			"app_name":     "AI & Data Workbench",
			"version":      "2.0.0",
			"nlp_mode":     fmt.Sprintf("Local Analyzer (%s/%s)", runtime.GOOS, runtime.GOARCH),
			"entities":     allEntities,
			"custom_rules": customRules,
			"samples":      sampleTexts,
		})
	})

	mux.HandleFunc("/api/mask-text", func(w http.ResponseWriter, r *http.Request) {
		t0 := time.Now()
		var req struct {
			Text            string     `json:"text"`
			Config          MaskConfig `json:"config"`
			DisabledIndices []int      `json:"disabled_indices"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"detail": err.Error()})
			return
		}
		res := maskTextNative(req.Text, req.Config, req.DisabledIndices, nil)
		res["elapsed_ms"] = float64(time.Since(t0).Microseconds()) / 1000.0
		writeJSON(w, 200, res)
	})

	mux.HandleFunc("/api/restore-text", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Text     string            `json:"text"`
			TokenMap map[string]string `json:"token_map"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		restored, cnt := restoreTextNative(req.Text, req.TokenMap)
		writeJSON(w, 200, map[string]interface{}{
			"restored_text":  restored,
			"restored_count": cnt,
		})
	})

	mux.HandleFunc("/api/custom-rules", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var cr CustomRule
			_ = json.NewDecoder(r.Body).Decode(&cr)
			cr.EntityType = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(cr.EntityType), " ", "_"))
			if cr.Score <= 0 {
				cr.Score = 0.85
			}
			var filtered []CustomRule
			for _, existing := range customRules {
				if existing.EntityType != cr.EntityType {
					filtered = append(filtered, existing)
				}
			}
			customRules = append(filtered, cr)
			writeJSON(w, 200, map[string]interface{}{
				"status":       "ok",
				"rule":         cr,
				"custom_rules": customRules,
			})
			return
		}
	})

	mux.HandleFunc("/api/custom-rules/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			etype := strings.TrimPrefix(r.URL.Path, "/api/custom-rules/")
			etype = strings.ToUpper(strings.TrimSpace(etype))
			var filtered []CustomRule
			for _, existing := range customRules {
				if existing.EntityType != etype {
					filtered = append(filtered, existing)
				}
			}
			customRules = filtered
			writeJSON(w, 200, map[string]interface{}{"status": "ok"})
		}
	})

	mux.HandleFunc("/api/excel/load-sample", func(w http.ResponseWriter, r *http.Request) {
		b, err := generateSampleExcelBytesNative()
		if err != nil {
			writeJSON(w, 500, map[string]string{"detail": err.Error()})
			return
		}
		fname := "sample_pii_thai_eng.xlsx"
		info, err := inspectTabularNative(b, fname)
		if err != nil {
			writeJSON(w, 500, map[string]string{"detail": err.Error()})
			return
		}
		uid := fmt.Sprintf("job_%d", time.Now().UnixNano())
		jobStoreMu.Lock()
		jobStore[uid] = &JobEntry{RawBytes: b, Filename: fname, CreatedAt: time.Now()}
		jobStoreMu.Unlock()
		info["upload_id"] = uid
		writeJSON(w, 200, info)
	})

	mux.HandleFunc("/api/excel/inspect", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseMultipartForm(64 << 20)
		file, hdr, err := r.FormFile("file")
		if err != nil {
			writeJSON(w, 400, map[string]string{"detail": err.Error()})
			return
		}
		defer file.Close()
		b, _ := io.ReadAll(file)
		fname := hdr.Filename
		info, err := inspectTabularNative(b, fname)
		if err != nil {
			writeJSON(w, 400, map[string]string{"detail": err.Error()})
			return
		}
		uid := fmt.Sprintf("up_%d", time.Now().UnixNano())
		jobStoreMu.Lock()
		jobStore[uid] = &JobEntry{RawBytes: b, Filename: fname, CreatedAt: time.Now()}
		jobStoreMu.Unlock()
		info["upload_id"] = uid
		writeJSON(w, 200, info)
	})

	mux.HandleFunc("/api/excel/mask", func(w http.ResponseWriter, r *http.Request) {
		t0 := time.Now()
		_ = r.ParseMultipartForm(64 << 20)
		uploadID := r.FormValue("upload_id")
		jobStoreMu.Lock()
		entry, ok := jobStore[uploadID]
		jobStoreMu.Unlock()
		if !ok || entry == nil {
			writeJSON(w, 400, map[string]string{"detail": "Upload ID not found"})
			return
		}

		var cfg MaskConfig
		_ = json.Unmarshal([]byte(r.FormValue("config_json")), &cfg)
		var selSheets []string
		_ = json.Unmarshal([]byte(r.FormValue("selected_sheets_json")), &selSheets)
		var selCols map[string][]string
		_ = json.Unmarshal([]byte(r.FormValue("selected_columns_json")), &selCols)
		forceMask := r.FormValue("force_mask_selected_columns") == "true"
		incAudit := r.FormValue("include_audit_sheet") == "true"

		res, err := maskTabularNative(entry.RawBytes, entry.Filename, cfg, selSheets, selCols, forceMask, incAudit)
		if err != nil {
			writeJSON(w, 500, map[string]string{"detail": err.Error()})
			return
		}

		jobID := fmt.Sprintf("masked_%d", time.Now().UnixNano())
		outBytes := res["output_bytes"].([]byte)
		outName := res["filename"].(string)
		tokMap := res["token_map"].(map[string]string)

		jobStoreMu.Lock()
		jobStore[jobID] = &JobEntry{
			OutputBytes: outBytes,
			Filename:    outName,
			TokenMap:    tokMap,
			CreatedAt:   time.Now(),
		}
		jobStoreMu.Unlock()

		writeJSON(w, 200, map[string]interface{}{
			"job_id":              jobID,
			"filename":            outName,
			"total_cells_scanned": res["total_cells_scanned"],
			"total_cells_masked":  res["total_cells_masked"],
			"entity_counts":       res["entity_counts"],
			"sheet_previews":      res["sheet_previews"],
			"token_map":           tokMap,
			"elapsed_ms":          float64(time.Since(t0).Microseconds()) / 1000.0,
		})
	})

	mux.HandleFunc("/api/excel/download/", func(w http.ResponseWriter, r *http.Request) {
		jobID := strings.TrimPrefix(r.URL.Path, "/api/excel/download/")
		jobStoreMu.Lock()
		entry, ok := jobStore[jobID]
		jobStoreMu.Unlock()
		if !ok || entry == nil || len(entry.OutputBytes) == 0 {
			http.NotFound(w, r)
			return
		}
		if strings.HasSuffix(strings.ToLower(entry.Filename), ".csv") {
			w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		} else {
			w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
		}
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, entry.Filename))
		_, _ = w.Write(entry.OutputBytes)
	})

	mux.HandleFunc("/api/excel/restore", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseMultipartForm(64 << 20)
		file, hdr, err := r.FormFile("file")
		if err != nil {
			writeJSON(w, 400, map[string]string{"detail": err.Error()})
			return
		}
		defer file.Close()
		b, _ := io.ReadAll(file)
		var tokMap map[string]string
		_ = json.Unmarshal([]byte(r.FormValue("token_map_json")), &tokMap)

		outBytes, totalRestored, err := restoreTabularNative(b, hdr.Filename, tokMap)
		if err != nil {
			writeJSON(w, 400, map[string]string{"detail": err.Error()})
			return
		}
		jobID := fmt.Sprintf("restored_%d", time.Now().UnixNano())
		outName := "restored_" + hdr.Filename
		jobStoreMu.Lock()
		jobStore[jobID] = &JobEntry{
			OutputBytes: outBytes,
			Filename:    outName,
			CreatedAt:   time.Now(),
		}
		jobStoreMu.Unlock()
		writeJSON(w, 200, map[string]interface{}{
			"job_id":         jobID,
			"filename":       outName,
			"total_restored": totalRestored,
		})
	})

	return mux
}

func openAppWindow(url string) {
	switch runtime.GOOS {
	case "windows":
		// Try Microsoft Edge / Chrome in Native App Window mode (--app=...) first
		edgePaths := []string{
			`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
			`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
		}
		for _, p := range edgePaths {
			if _, err := os.Stat(p); err == nil {
				_ = exec.Command(p, "--app="+url, "--window-size=1420,900").Start()
				return
			}
		}
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		// Check if Chrome/Edge/Brave exists for chromeless app window, or open Safari/default browser
		chromeApp := "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
		if _, err := os.Stat(chromeApp); err == nil {
			_ = exec.Command(chromeApp, "--app="+url, "--window-size=1420,900").Start()
			return
		}
		_ = exec.Command("open", url).Start()
	default:
		_ = exec.Command("xdg-open", url).Start()
	}
}

func extractEmbeddedPythonApp(destDir string) {
	_ = fs.WalkDir(embeddedPythonSrc, "python_src", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel("python_src", path)
		target := filepath.Join(destDir, rel)
		_ = os.MkdirAll(filepath.Dir(target), 0755)
		data, err := embeddedPythonSrc.ReadFile(path)
		if err == nil {
			_ = os.WriteFile(target, data, 0644)
		}
		return nil
	})
}

func runWindowsInstallerIfRequested() bool {
	if runtime.GOOS != "windows" {
		return false
	}
	exePath, err := os.Executable()
	if err != nil {
		return false
	}
	exeName := strings.ToLower(filepath.Base(exePath))
	if !strings.Contains(exeName, "setup") && !strings.Contains(exeName, "install") {
		return false
	}

	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		return false
	}
	installDir := filepath.Join(localAppData, "Programs", "PresidioShield")
	_ = os.MkdirAll(installDir, 0755)
	targetExe := filepath.Join(installDir, "PresidioShield.exe")

	// Copy current executable to targetExe
	if data, err := os.ReadFile(exePath); err == nil {
		_ = os.WriteFile(targetExe, data, 0755)
	}
	// Also extract the Python Presidio source files alongside it
	extractEmbeddedPythonApp(filepath.Join(installDir, "presidio_python"))

	// Create Desktop & Start Menu shortcuts using PowerShell WScript.Shell
	psScript := fmt.Sprintf(`
$WshShell = New-Object -ComObject WScript.Shell
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$Shortcut = $WshShell.CreateShortcut("$DesktopPath\Presidio Shield Desktop.lnk")
$Shortcut.TargetPath = "%s"
$Shortcut.WorkingDirectory = "%s"
$Shortcut.Description = "Presidio Shield Desktop - PII Masking & Redaction"
$Shortcut.Save()
`, targetExe, installDir)
	_ = exec.Command("powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", psScript).Run()

	// Launch installed executable and exit installer
	_ = exec.Command(targetExe).Start()
	return true
}

// Keep unused zip import valid
var _ = zip.NewReader
var _ = strconv.Itoa

func main() {
	if runWindowsInstallerIfRequested() {
		return
	}

	// If running on macOS inside PresidioShield.app and local .venv with pywebview exists, delegate to it for full spaCy + PyWebView
	exePath, _ := os.Executable()
	workspacePython := "/Users/asd1122/Desktop/pii_masking/.venv/bin/python"
	workspaceDesktopPy := "/Users/asd1122/Desktop/pii_masking/desktop.py"
	if runtime.GOOS == "darwin" && os.Getenv("PRESIDIO_FORCE_NATIVE") == "" {
		if _, err := os.Stat(workspacePython); err == nil {
			if _, err2 := os.Stat(workspaceDesktopPy); err2 == nil {
				cmd := exec.Command(workspacePython, workspaceDesktopPy)
				cmd.Dir = "/Users/asd1122/Desktop/pii_masking"
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				if err := cmd.Run(); err == nil {
					return
				}
			}
		}
	}
	_ = exePath

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		os.Exit(1)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	url := fmt.Sprintf("http://127.0.0.1:%d", port)

	go func() {
		time.Sleep(350 * time.Millisecond)
		openAppWindow(url)
	}()

	srv := &http.Server{
		Handler: buildHTTPMux(),
	}
	_ = srv.Serve(ln)
}
