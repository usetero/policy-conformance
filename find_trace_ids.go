// +build ignore

package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
)

const maxThreshold = uint64(1) << 56

// Go/Rust OTel algorithm: extract last 7 bytes as 56-bit R, keep if R >= T
// where T = (1 - percentage/100) * 2^56
func otelShouldKeep(traceIDBytes []byte, percentage float64) bool {
	if percentage >= 100 {
		return true
	}
	if percentage <= 0 {
		return false
	}
	// Extract last 7 bytes (56 bits)
	var r uint64
	for _, b := range traceIDBytes[9:16] {
		r = (r << 8) | uint64(b)
	}
	threshold := uint64((1.0 - percentage/100.0) * float64(maxThreshold))
	return r >= threshold
}

// Zig algorithm: hashTraceId -> splitmix64 -> % 100 < percentage
func zigShouldKeep(traceIDHex string, percentage uint8) bool {
	if percentage == 0 {
		return false
	}
	if percentage >= 100 {
		return true
	}
	hashVal := hashTraceIdZig(traceIDHex)
	mixed := splitmix64(hashVal)
	bucket := uint8(mixed % 100)
	return bucket < percentage
}

func hashTraceIdZig(hexStr string) uint64 {
	if len(hexStr) == 0 {
		return 0
	}
	start := 0
	if len(hexStr) > 14 {
		start = len(hexStr) - 14
	}
	var hash uint64
	for _, c := range hexStr[start:] {
		var nibble uint64
		switch {
		case c >= '0' && c <= '9':
			nibble = uint64(c - '0')
		case c >= 'a' && c <= 'f':
			nibble = uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			nibble = uint64(c-'A') + 10
		default:
			nibble = 0
		}
		hash = (hash << 4) | nibble
	}
	return hash
}

func splitmix64(x uint64) uint64 {
	h := x + 0x9e3779b97f4a7c15
	h = (h ^ (h >> 30)) * 0xbf58476d1ce4e5b9
	h = (h ^ (h >> 27)) * 0x94d049bb133111eb
	return h ^ (h >> 31)
}

func main() {
	// Percentages we need to test
	percentages := []float64{10, 25, 50, 75}

	// We need 5 spans with different "threshold levels" such that:
	// At 10%: only 1 kept
	// At 25%: exactly 2 kept
	// At 50%: exactly 3 kept
	// At 75%: exactly 4 kept
	// (At 100%: all 5 kept - trivial)
	//
	// So we need spans that transition from kept to dropped at roughly:
	// Span A: always kept (kept at >=1%, i.e. both algorithms agree to keep at 10,25,50,75)
	// Span B: kept at >=25% (kept at 25,50,75 but not 10)
	// Span C: kept at >=50% (kept at 50,75 but not 10,25)
	// Span D: kept at >=75% (kept at 75 but not 10,25,50)
	// Span E: never kept at any test pct (not kept at 10,25,50,75)

	// Brute force: try trace IDs with fixed prefix and varying last 7 bytes
	prefix := [9]byte{0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00, 0x00, 0x00, 0x00}

	type Candidate struct {
		bytes      [16]byte
		hexStr     string
		base64Str  string
		otelR      uint64
		zigBucket  uint8
	}

	// For each desired behavior, search
	type DesiredBehavior struct {
		name string
		// For each percentage, whether it should be kept
		keepAt10  bool
		keepAt25  bool
		keepAt50  bool
		keepAt75  bool
	}

	behaviors := []DesiredBehavior{
		{"spanA", true, true, true, true},
		{"spanB", false, true, true, true},
		{"spanC", false, false, true, true},
		{"spanD", false, false, false, true},
		{"spanE", false, false, false, false},
	}

	for _, b := range behaviors {
		fmt.Printf("Searching for %s (keep@10=%v, keep@25=%v, keep@50=%v, keep@75=%v)...\n",
			b.name, b.keepAt10, b.keepAt25, b.keepAt50, b.keepAt75)

		found := false
		// Try different last 7 bytes
		for hi := uint32(0); hi < 256 && !found; hi++ {
			for lo := uint64(0); lo < (1<<24) && !found; lo++ {
				var traceID [16]byte
				copy(traceID[:9], prefix[:])
				// Set last 7 bytes
				traceID[9] = byte(hi)
				traceID[10] = byte(lo >> 40)
				traceID[11] = byte(lo >> 32)
				traceID[12] = byte(lo >> 24)
				traceID[13] = byte(lo >> 16)
				traceID[14] = byte(lo >> 8)
				traceID[15] = byte(lo)

				hexStr := hex.EncodeToString(traceID[:])

				// Check all percentages for both algorithms
				allMatch := true
				for _, pct := range percentages {
					otelKeep := otelShouldKeep(traceID[:], pct)
					zigKeep := zigShouldKeep(hexStr, uint8(pct))

					var desired bool
					switch pct {
					case 10:
						desired = b.keepAt10
					case 25:
						desired = b.keepAt25
					case 50:
						desired = b.keepAt50
					case 75:
						desired = b.keepAt75
					}

					if otelKeep != desired || zigKeep != desired {
						allMatch = false
						break
					}
				}

				if allMatch {
					b64 := base64.StdEncoding.EncodeToString(traceID[:])

					// Also compute the OTel R value for reference
					var r uint64
					for _, b := range traceID[9:16] {
						r = (r << 8) | uint64(b)
					}
					rPct := float64(r) / float64(maxThreshold) * 100

					zigHash := hashTraceIdZig(hexStr)
					zigMixed := splitmix64(zigHash)
					zigBucket := zigMixed % 100

					fmt.Printf("  FOUND: hex=%s base64=%s\n", hexStr, b64)
					fmt.Printf("    OTel R=%d (%.2f%%), Zig bucket=%d\n", r, rPct, zigBucket)

					// Verify
					for _, pct := range percentages {
						otelKeep := otelShouldKeep(traceID[:], pct)
						zigKeep := zigShouldKeep(hexStr, uint8(pct))
						fmt.Printf("    @%v%%: otel=%v zig=%v\n", pct, otelKeep, zigKeep)
					}
					found = true
				}
			}
		}
		if !found {
			fmt.Printf("  NOT FOUND in first pass, trying wider range...\n")

			// Try random values with wider range
			for trial := uint64(0); trial < (1<<32) && !found; trial++ {
				var traceID [16]byte
				copy(traceID[:9], prefix[:])
				binary.BigEndian.PutUint32(traceID[9:13], uint32(trial>>16))
				traceID[13] = byte(trial >> 8)
				traceID[14] = byte(trial)
				traceID[15] = byte(trial >> 24)

				hexStr := hex.EncodeToString(traceID[:])

				allMatch := true
				for _, pct := range percentages {
					otelKeep := otelShouldKeep(traceID[:], pct)
					zigKeep := zigShouldKeep(hexStr, uint8(pct))

					var desired bool
					switch pct {
					case 10:
						desired = b.keepAt10
					case 25:
						desired = b.keepAt25
					case 50:
						desired = b.keepAt50
					case 75:
						desired = b.keepAt75
					}

					if otelKeep != desired || zigKeep != desired {
						allMatch = false
						break
					}
				}

				if allMatch {
					b64 := base64.StdEncoding.EncodeToString(traceID[:])
					var r uint64
					for _, byt := range traceID[9:16] {
						r = (r << 8) | uint64(byt)
					}
					rPct := float64(r) / float64(maxThreshold) * 100

					_ = math.Abs(0) // use math

					zigHash := hashTraceIdZig(hexStr)
					zigMixed := splitmix64(zigHash)
					zigBucket := zigMixed % 100

					fmt.Printf("  FOUND: hex=%s base64=%s\n", hexStr, b64)
					fmt.Printf("    OTel R=%d (%.2f%%), Zig bucket=%d\n", r, rPct, zigBucket)

					for _, pct := range percentages {
						otelKeep := otelShouldKeep(traceID[:], pct)
						zigKeep := zigShouldKeep(hexStr, uint8(pct))
						fmt.Printf("    @%v%%: otel=%v zig=%v\n", pct, otelKeep, zigKeep)
					}
					found = true
				}
			}
			if !found {
				fmt.Printf("  STILL NOT FOUND after extended search\n")
			}
		}
		fmt.Println()
	}
}
