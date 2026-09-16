package cryptopro

import "strings"

const (
	exactPrefix = "[ErrorCode: 0x"
	markerName  = "ErrorCode:"
)

// ErrorCodeScanner extracts only standalone `[ErrorCode: 0x........]` lines
// from a provider stream. It never retains the raw payload.
type ErrorCodeScanner struct {
	prefixOffset         int
	ignoredMarkerOffset  int
	candidate            string
	atLineStart          bool
	ignoringLine         bool
	readingCode          bool
	awaitingCloseBracket bool
	awaitingLineEnd      bool
	sawCarriageReturn    bool
	malformed            bool
	finished             bool
	codes                []string
}

func NewErrorCodeScanner() *ErrorCodeScanner {
	return &ErrorCodeScanner{atLineStart: true}
}

func (s *ErrorCodeScanner) Consume(chunk []byte) {
	if s.finished {
		panic("cryptopro: output scanner is already finished")
	}
	for i := 0; i < len(chunk); i++ {
		s.consumeByte(chunk[i])
	}
}

// Codes returns the collected lowercase hex codes, or nil if a marker line
// was malformed. The scanner is finished after the first call.
func (s *ErrorCodeScanner) Codes() []string {
	if !s.finished {
		if s.awaitingLineEnd {
			s.codes = append(s.codes, s.candidate)
		} else if s.readingCode || s.awaitingCloseBracket {
			s.malformed = true
		} else if s.prefixOffset >= len("[ErrorCode:") {
			s.malformed = true
		}
		s.finished = true
	}
	if s.malformed {
		return nil
	}
	out := make([]string, len(s.codes))
	copy(out, s.codes)
	return out
}

func (s *ErrorCodeScanner) consumeByte(b byte) {
	if s.ignoringLine {
		if b == '\n' {
			s.resetLine()
			return
		}
		s.scanIgnoredByteForMarker(b)
		return
	}

	if s.awaitingLineEnd {
		if b == '\n' {
			s.codes = append(s.codes, s.candidate)
			s.resetLine()
			return
		}
		if b == '\r' && !s.sawCarriageReturn {
			s.sawCarriageReturn = true
			return
		}
		s.rejectCurrentLine()
		return
	}

	if s.awaitingCloseBracket {
		if b == ']' {
			s.awaitingCloseBracket = false
			s.awaitingLineEnd = true
			return
		}
		s.rejectCurrentLine()
		return
	}

	if s.readingCode {
		if !isHexadecimal(b) {
			s.rejectCurrentLine()
			return
		}
		s.candidate += strings.ToLower(string(b))
		if len(s.candidate) == 8 {
			s.readingCode = false
			s.awaitingCloseBracket = true
		}
		return
	}

	if s.atLineStart {
		if b == '\n' {
			return
		}
		s.atLineStart = false
		if b == exactPrefix[0] {
			s.prefixOffset = 1
			return
		}
		s.ignoringLine = true
		s.scanIgnoredByteForMarker(b)
		return
	}

	if s.prefixOffset < len(exactPrefix) && b == exactPrefix[s.prefixOffset] {
		s.prefixOffset++
		if s.prefixOffset == len(exactPrefix) {
			s.prefixOffset = 0
			s.readingCode = true
		}
		return
	}

	if s.prefixOffset >= len("[ErrorCode:") {
		s.malformed = true
	}
	s.prefixOffset = 0
	s.ignoringLine = true
	s.scanIgnoredByteForMarker(b)
}

func (s *ErrorCodeScanner) scanIgnoredByteForMarker(b byte) {
	if s.ignoredMarkerOffset < len(markerName) && b == markerName[s.ignoredMarkerOffset] {
		s.ignoredMarkerOffset++
		if s.ignoredMarkerOffset == len(markerName) {
			s.malformed = true
			s.ignoredMarkerOffset = 0
		}
		return
	}
	if b == markerName[0] {
		s.ignoredMarkerOffset = 1
		return
	}
	s.ignoredMarkerOffset = 0
}

func (s *ErrorCodeScanner) rejectCurrentLine() {
	s.malformed = true
	s.prefixOffset = 0
	s.candidate = ""
	s.readingCode = false
	s.awaitingCloseBracket = false
	s.awaitingLineEnd = false
	s.sawCarriageReturn = false
	s.ignoringLine = true
	s.ignoredMarkerOffset = 0
}

func (s *ErrorCodeScanner) resetLine() {
	s.prefixOffset = 0
	s.ignoredMarkerOffset = 0
	s.candidate = ""
	s.atLineStart = true
	s.ignoringLine = false
	s.readingCode = false
	s.awaitingCloseBracket = false
	s.awaitingLineEnd = false
	s.sawCarriageReturn = false
}

func isHexadecimal(b byte) bool {
	return strings.ContainsRune("0123456789abcdefABCDEF", rune(b))
}
