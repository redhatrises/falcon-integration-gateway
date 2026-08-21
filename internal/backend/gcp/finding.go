package gcp

import (
	"strconv"
	"strings"
)

// findingIDMaxLen is the maximum length of an SCC finding id. The composed id
// is clamped to its trailing findingIDMaxLen characters.
const findingIDMaxLen = 32

// findingIDCreationHexLen is the number of trailing hexadecimal characters of
// the event creation time appended to the finding id.
const findingIDCreationHexLen = 6

// findingID derives a stable, SCC-acceptable finding id from a Falcon event id
// and its creation time in epoch milliseconds. Non-alphanumeric characters are
// removed from the event id, the trailing six characters of the "0x"-prefixed
// hexadecimal creation time are appended, and the result is clamped to its last
// 32 characters. For a creation time whose hex form is shorter than six
// characters the "0x" prefix is retained, so ids stay stable against findings
// the upstream gateway already wrote.
func findingID(eventID string, eventCreationTime int64) string {
	stripped := stripNonAlphanumeric(eventID)
	suffix := lastChars(hexWithPrefix(eventCreationTime), findingIDCreationHexLen)
	return lastChars(stripped+suffix, findingIDMaxLen)
}

// severity maps a Falcon severity name to the SCC finding severity. The value
// is uppercased; "INFORMATIONAL" is remapped to "LOW" because SCC has no
// informational level.
func severity(name string) string {
	upper := strings.ToUpper(name)
	if upper == "INFORMATIONAL" {
		return "LOW"
	}
	return upper
}

// stripNonAlphanumeric removes every character that is not an ASCII letter or
// digit.
func stripNonAlphanumeric(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// hexWithPrefix renders n as a "0x"-prefixed (or "-0x" for negatives) lowercase
// base-16 string. The "0x" prefix is intentional: it is part of the finding-id
// suffix and must be retained so ids stay stable across the gateway's history.
func hexWithPrefix(n int64) string {
	if n < 0 {
		return "-0x" + strconv.FormatInt(-n, 16)
	}
	return "0x" + strconv.FormatInt(n, 16)
}

// lastChars returns the trailing n characters of s, or all of s when it is
// shorter than n.
func lastChars(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
