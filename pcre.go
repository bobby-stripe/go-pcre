// Copyright (c) 2011 Florian Weimer. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// * Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in the
//   documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Package pcre provides access to the Perl Compatible Regular
// Expresion library, PCRE.
//
// It implements two main types, Regexp and Matcher.  Regexp objects
// store a compiled regular expression. They consist of two immutable
// parts: pcre and pcre_extra. Compile()/MustCompile() initialize pcre.
// Calling Study() on a compiled Regexp initializes pcre_extra.
// Compilation of regular expressions using Compile or MustCompile is
// slightly expensive, so these objects should be kept and reused,
// instead of compiling them from scratch for each matching attempt.
// CompileJIT and MustCompileJIT are way more expensive, because they
// run Study() after compiling a Regexp, but they tend to give
// much better perfomance:
// http://sljit.sourceforge.net/regex_perf.html
//
// Matcher objects keeps the results of a match against a []byte or
// string subject.  The Group and GroupString functions provide access
// to capture groups; both versions work no matter if the subject was a
// []byte or string, but the version with the matching type is slightly
// more efficient.
//
// Matcher objects contain some temporary space and refer the original
// subject.  They are mutable and can be reused (using Match,
// MatchString, Reset or ResetString).
//
// For details on the regular expression language implemented by this
// package and the flags defined below, see the PCRE documentation.
// http://www.pcre.org/pcre.txt
package pcre

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"github.com/bobby-stripe/gasm/wasi"
	"github.com/bobby-stripe/gasm/wasm"
	"github.com/bobby-stripe/gasm/wasm/naivevm"
)

//go:generate bash define-constants.bash

//go:embed libpcre2.wasm
var libpcre2WasmBytecode []byte

type pcreModule struct {
	vm             *wasm.Store
	mu             sync.Mutex
	errorCodePtr   uint64
	errorOffsetPtr uint64
}

func (m *pcreModule) mem() []byte {
	return m.vm.Memories[0].Memory
}

// callocLocked calls malloc, then zeros the buffer
func (m *pcreModule) callocLocked(len uint64) uint64 {
	results, _, err := m.vm.CallFunction("main", "malloc", len)
	if err != nil {
		// this is a build-time error caught by tests
		panic(fmt.Errorf("malloc Exec failed: %w", err))
	}
	ptr := results[0]

	mem := m.mem()
	for i := uint64(0); i < len; i++ {
		mem[ptr+i] = 0
	}

	return ptr
}

func (m *pcreModule) freeLocked(ptr uint64) {
	_, _, err := m.vm.CallFunction("main", "free", ptr)
	if err != nil {
		// this is a build-time error caught by tests
		panic(fmt.Errorf("free Exec failed: %w", err))
	}
}

func (m *pcreModule) clearLastErrorLocked() {
	mem := m.mem()

	binary.LittleEndian.PutUint32(mem[m.errorCodePtr:m.errorCodePtr+4], 0)
	binary.LittleEndian.PutUint32(mem[m.errorOffsetPtr:m.errorOffsetPtr+4], 0)
}

func (m *pcreModule) readUint32(ptr uint64) uint32 {
	mem := m.mem()
	return binary.LittleEndian.Uint32(mem[ptr : ptr+4])
}

func (m *pcreModule) getLastErrorLocked(pattern string) *CompileError {
	errorCode := m.readUint32(m.errorCodePtr)
	if errorCode == 0 {
		// no error? super
		return nil
	}

	errorBufLen := uint64(128)
	errorBufPtr := m.callocLocked(errorBufLen)
	defer m.freeLocked(errorBufPtr)

	_, _, err := m.vm.CallFunction("main", "pcre2_get_error_message_8", uint64(errorCode), errorBufPtr, 127)
	if err != nil {
		panic(fmt.Errorf("call(_pcre2_get_error_message_8): %w", err))
	}

	mem := m.mem()
	nullOff := uint64(bytes.IndexByte(mem[errorBufPtr:errorBufPtr+errorBufLen], 0))

	message := string(mem[errorBufPtr : errorBufPtr+nullOff])

	offset := m.readUint32(m.errorOffsetPtr)

	return &CompileError{
		Pattern: pattern,
		Message: message,
		Offset:  int(offset),
	}
}

func (m *pcreModule) allocRegexpLocked(regexp Regexp) uint64 {
	reLen := uint64(len(regexp.ptr))
	ptr := m.callocLocked(reLen)
	mem := m.mem()
	copy(mem[ptr:ptr+reLen], regexp.ptr)

	return ptr
}

func (m *pcreModule) copyOutRegexpLocked(rePtr uint64) []byte {
	reLen := m.patternInfoLocked(rePtr, INFO_SIZE)
	pattern := make([]byte, reLen)
	mem := m.mem()
	copy(pattern, mem[rePtr:rePtr+uint64(reLen)])
	return pattern
}

func (m *pcreModule) Compile(pattern string, flags int) (Regexp, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if nullOffset := strings.IndexByte(pattern, 0); nullOffset >= 0 {
		return Regexp{}, &CompileError{
			Pattern: pattern,
			Message: "NUL byte in pattern",
			Offset:  nullOffset,
		}
	}

	patternLen := uint64(len(pattern))
	patternPtr := m.callocLocked(patternLen + 1) // for trailing null, Just In Case
	defer m.freeLocked(patternPtr)

	mem := m.mem()
	copy(mem[patternPtr:patternPtr+patternLen], pattern)

	results, _, err := m.vm.CallFunction("main", "pcre2_compile_8", patternPtr, patternLen, uint64(flags), m.errorCodePtr, m.errorOffsetPtr, 0)
	if err != nil {
		panic(fmt.Errorf("call(_pcre2_compile_8): %w", err))
	}
	ptr := results[0]
	if ptr == 0 {
		return Regexp{}, m.getLastErrorLocked(pattern)
	}
	defer m.freeLocked(ptr)

	reCode := m.copyOutRegexpLocked(ptr)

	return Regexp{ptr: reCode}, nil
}

func (m *pcreModule) patternInfoLocked(rePtr uint64, info int) int {
	resultPtr := m.callocLocked(4)
	defer m.freeLocked(resultPtr)

	_, _, err := m.vm.CallFunction("main", "pcre2_pattern_info_8", rePtr, uint64(info), resultPtr)
	if err != nil {
		panic(fmt.Errorf("call(pcre2_pattern_info_8): %w", err))
	}
	return int(m.readUint32(resultPtr))
}

func (m *pcreModule) captureCount(re Regexp) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	rePtr := m.allocRegexpLocked(re)
	defer m.freeLocked(rePtr)

	return m.patternInfoLocked(rePtr, INFO_CAPTURECOUNT)
}

func (m *pcreModule) substringNumberFromName(re Regexp, name string) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	rePtr := m.allocRegexpLocked(re)
	defer m.freeLocked(rePtr)

	nameLen := len(name)
	namePtr := m.callocLocked(uint64(nameLen) + 1)
	defer m.freeLocked(namePtr)

	mem := m.mem()
	copy(mem[namePtr:namePtr+uint64(nameLen)], name)

	results, _, err := m.vm.CallFunction("main", "pcre2_substring_number_from_name_8", rePtr, namePtr)
	if err != nil {
		panic(fmt.Errorf("call(pcre2_substring_number_from_name_8): %w", err))
	}
	return int(results[0])
}

func (m *pcreModule) match(match *Matcher, subject []byte, length int, flags int) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	rePtr := m.allocRegexpLocked(match.re)
	defer m.freeLocked(rePtr)

	subjectPtr := m.callocLocked(uint64(length))
	defer m.freeLocked(subjectPtr)

	mem := m.mem()
	copy(mem[subjectPtr:subjectPtr+uint64(length)], subject)

	results, _, err := m.vm.CallFunction("main", "pcre2_match_data_create_from_pattern_8", rePtr, 0)
	if err != nil {
		panic(fmt.Errorf("call(pcre2_match_data_create_from_pattern_8): %w", err))
	}
	matchData := results[0]
	defer func(matchData uint64) {
		_, _, err := m.vm.CallFunction("main", "pcre2_match_data_free_8", matchData)
		if err != nil {
			panic(fmt.Errorf("call(pcre2_match_data_free_8): %w", err))
		}
	}(matchData)

	results, _, err = m.vm.CallFunction("main", "pcre2_match_8", rePtr, subjectPtr, uint64(length), 0, uint64(flags), matchData, 0)
	if err != nil {
		panic(fmt.Errorf("call(pcre2_match_8): %w", err))
	}

	matchCount := int(results[0])

	results, _, err = m.vm.CallFunction("main", "pcre2_get_ovector_count_8", matchData)
	if err != nil {
		panic(fmt.Errorf("call(pcre2_get_ovector_count_8): %w", err))
	}
	ovecLen := int(results[0])
	if ovecLen*3 != len(match.ovector) {
		panic(fmt.Errorf("expected ovector lengths to match, but %d != %d", ovecLen*3, len(match.ovector)))
	}

	results, _, err = m.vm.CallFunction("main", "pcre2_get_ovector_pointer_8", matchData)
	if err != nil {
		panic(fmt.Errorf("call(pcre2_get_ovector_pointer_8): %w", err))
	}
	ovecPtr := int(results[0])

	for i := 0; i < ovecLen*2; i++ {
		entryPtr := ovecPtr + i*4
		entry := mem[entryPtr : entryPtr+4]
		match.ovector[i] = int(binary.LittleEndian.Uint32(entry))
	}

	return matchCount
}

func newPcreModule() *pcreModule {
	mod, err := wasm.DecodeModule(libpcre2WasmBytecode)
	if err != nil {
		panic(fmt.Errorf("decode module failed: %w", err))
	}

	vm := wasm.NewStore(naivevm.NewEngine())

	err = wasi.NewEnvironment().Register(vm)
	if err != nil {
		panic(fmt.Errorf("Register() failed: %w", err))
	}

	_ = vm.AddHostFunction("env", "emscripten_notify_memory_growth", reflect.ValueOf(notifyStub))

	err = vm.Instantiate(mod, "main")
	if err != nil {
		panic(fmt.Errorf("InstantiateModule() failed: %w", err))
	}

	_, _, err = vm.CallFunction("main", "_initialize")
	if err != nil {
		panic(fmt.Errorf("exec initialize() failed: %w", err))
	}

	m := &pcreModule{
		vm: vm,
	}

	// alloc space for error information once -- we only call into libpcre2
	// when holding a mutex, so this "global" state is fine.
	m.errorCodePtr = m.callocLocked(4)
	m.errorOffsetPtr = m.callocLocked(4)

	return m
}

var mod *pcreModule

func notifyStub(_vm *wasm.Store, _len int32) {
}

func init() {
	mod = newPcreModule()
}

// Regexp holds a reference to a compiled regular expression.
// Use Compile or MustCompile to create such objects.
type Regexp struct {
	ptr []byte
}

// Compile the pattern and return a compiled regexp.
// If compilation fails, the second return value holds a *CompileError.
func Compile(pattern string, flags int) (Regexp, error) {
	return mod.Compile(pattern, flags)
}

// MustCompile compiles the pattern.  If compilation fails, panic.
func MustCompile(pattern string, flags int) (re Regexp) {
	re, err := Compile(pattern, flags)
	if err != nil {
		panic(err)
	}
	return
}

// Matcher creates a new matcher object, with the byte slice as subject.
// It also starts a first match on subject. Test for success with Matches().
func (re Regexp) Matcher(subject []byte, flags int) (m *Matcher) {
	m = re.NewMatcher()
	m.Match(subject, flags)
	return
}

// NewMatcher creates a new matcher object for the given Regexp.
func (re Regexp) NewMatcher() (m *Matcher) {
	m = new(Matcher)
	m.Init(&re)
	return
}

// Groups returns the number of capture groups in the compiled pattern.
func (re Regexp) Groups() int {
	if re.ptr == nil {
		panic("Regexp.Groups: uninitialized")
	}

	return mod.captureCount(re)
}

// MatcherString creates a new matcher, with the specified subject string.
// It also starts a first match on subject. Test for success with Matches().
func (re Regexp) MatcherString(subject string, flags int) (m *Matcher) {
	m = re.NewMatcher()
	m.MatchString(subject, flags)
	return
}

// Matcher objects provide a place for storing match results.
// They can be created by the Matcher and MatcherString functions,
// or they can be initialized with Reset or ResetString.
type Matcher struct {
	re        Regexp
	groups    int
	matchData uint64
	ovector   []int
	matches   bool   // last match was successful
	partial   bool   // was the last match a partial match?
	subjects  string // one of these fields is set to record the subject,
	subjectb  []byte // so that Group/GroupString can return slices
}

// Init binds an existing Matcher object to the given Regexp.
func (m *Matcher) Init(re *Regexp) {
	if re.ptr == nil {
		panic("Matcher.Init: uninitialized")
	}
	m.matches = false
	if m.re.ptr != nil && &m.re.ptr[0] == &re.ptr[0] {
		// Skip group count extraction if the matcher has
		// already been initialized with the same regular
		// expression.
		return
	}
	m.re = *re
	m.groups = re.Groups()
	if ovectorlen := 3 * (1 + m.groups); len(m.ovector) < ovectorlen {
		m.ovector = make([]int, ovectorlen)
	}
}

// Match tries to match the specified byte slice to
// the current pattern by calling Exec and collects the result.
// Returns true if the match succeeds.
func (m *Matcher) Match(subject []byte, flags int) bool {
	if m.re.ptr == nil {
		panic("Matcher.Match: uninitialized")
	}
	rc := m.Exec(subject, flags)
	m.matches = matched(rc)
	m.partial = (rc == ERROR_PARTIAL)
	return m.matches
}

// Reset switches the matcher object to the specified regexp and subject.
// It also starts a first match on subject.
func (m *Matcher) Reset(re Regexp, subject []byte, flags int) bool {
	*m = Matcher{}
	m.Init(&re)
	return m.Match(subject, flags)
}

// ResetString switches the matcher object to the given regexp and subject.
// It also starts a first match on subject.
func (m *Matcher) ResetString(re Regexp, subject string, flags int) bool {
	m.Init(&re)
	return m.MatchString(subject, flags)
}

var nullbyte = []byte{0}

// MatchString tries to match the specified subject string to
// the current pattern by calling ExecString and collects the result.
// Returns true if the match succeeds.
func (m *Matcher) MatchString(subject string, flags int) bool {
	if m.re.ptr == nil {
		panic("Matcher.MatchString: uninitialized")
	}
	rc := m.ExecString(subject, flags)
	m.matches = matched(rc)
	m.partial = (rc == ERROR_PARTIAL)
	return m.matches
}

// Exec tries to match the specified byte slice to
// the current pattern. Returns the raw pcre_exec error code.
func (m *Matcher) Exec(subject []byte, flags int) int {
	if m.re.ptr == nil {
		panic("Matcher.Exec: uninitialized")
	}
	length := len(subject)
	m.subjects = ""
	m.subjectb = subject
	if length == 0 {
		subject = nullbyte // make first character adressable
	}
	return m.exec(subject, length, flags)
}

// ExecString tries to match the specified subject string to
// the current pattern. It returns the raw pcre_exec error code.
func (m *Matcher) ExecString(subject string, flags int) int {
	if m.re.ptr == nil {
		panic("Matcher.ExecString: uninitialized")
	}
	length := len(subject)
	m.subjects = subject
	m.subjectb = nil
	if length == 0 {
		subject = "\000" // make first character addressable
	}
	subjectSlice := []byte(subject)
	return m.exec(subjectSlice, length, flags)
}

func (m *Matcher) exec(subject []byte, length, flags int) int {
	return mod.match(m, subject, length, flags)
}

// matched checks the return code of a pattern match for success.
func matched(rc int) bool {
	switch {
	case rc >= 0 || rc == ERROR_PARTIAL:
		return true
	case rc == ERROR_NOMATCH:
		return false
	case rc == ERROR_BADOPTION:
		panic("PCRE.Match: invalid option flag")
	}
	panic("unexpected return code from pcre_exec: " + strconv.Itoa(rc))
}

// Matches returns true if a previous call to Matcher, MatcherString, Reset,
// ResetString, Match or MatchString succeeded.
func (m *Matcher) Matches() bool {
	return m.matches
}

// Partial returns true if a previous call to Matcher, MatcherString, Reset,
// ResetString, Match or MatchString found a partial match.
func (m *Matcher) Partial() bool {
	return m.partial
}

// Groups returns the number of groups in the current pattern.
func (m *Matcher) Groups() int {
	return m.groups
}

// Present returns true if the numbered capture group is present in the last
// match (performed by Matcher, MatcherString, Reset, ResetString,
// Match, or MatchString).  Group numbers start at 1.  A capture group
// can be present and match the empty string.
func (m *Matcher) Present(group int) bool {
	return m.ovector[2*group] != 0xffffffff
}

// Group returns the numbered capture group of the last match (performed by
// Matcher, MatcherString, Reset, ResetString, Match, or MatchString).
// Group 0 is the part of the subject which matches the whole pattern;
// the first actual capture group is numbered 1.  Capture groups which
// are not present return a nil slice.
func (m *Matcher) Group(group int) []byte {
	start := m.ovector[2*group]
	end := m.ovector[2*group+1]
	if start >= 0 {
		if m.subjectb != nil {
			return m.subjectb[start:end]
		}
		return []byte(m.subjects[start:end])
	}
	return nil
}

// Extract returns a slice of byte slices for a single match.
// The first byte slice contains the complete match.
// Subsequent byte slices contain the captured groups.
// If there was no match then nil is returned.
func (m *Matcher) Extract() [][]byte {
	if !m.matches {
		return nil
	}
	extract := make([][]byte, m.groups+1)
	extract[0] = m.subjectb
	for i := 1; i <= m.groups; i++ {
		x0 := m.ovector[2*i]
		x1 := m.ovector[2*i+1]
		extract[i] = m.subjectb[x0:x1]
	}
	return extract
}

// ExtractString returns a slice of strings for a single match.
// The first string contains the complete match.
// Subsequent strings in the slice contain the captured groups.
// If there was no match then nil is returned.
func (m *Matcher) ExtractString() []string {
	if !m.matches {
		return nil
	}
	extract := make([]string, m.groups+1)
	extract[0] = m.subjects
	for i := 1; i <= m.groups; i++ {
		x0 := m.ovector[2*i]
		x1 := m.ovector[2*i+1]
		extract[i] = m.subjects[x0:x1]
	}
	return extract
}

// GroupIndices returns the numbered capture group positions of the last
// match (performed by Matcher, MatcherString, Reset, ResetString, Match,
// or MatchString). Group 0 is the part of the subject which matches
// the whole pattern; the first actual capture group is numbered 1.
// Capture groups which are not present return a nil slice.
func (m *Matcher) GroupIndices(group int) []int {
	start := m.ovector[2*group]
	end := m.ovector[2*group+1]
	if start >= 0 {
		return []int{int(start), int(end)}
	}
	return nil
}

// GroupString returns the numbered capture group as a string.  Group 0
// is the part of the subject which matches the whole pattern; the first
// actual capture group is numbered 1.  Capture groups which are not
// present return an empty string.
func (m *Matcher) GroupString(group int) string {
	start := m.ovector[2*group]
	end := m.ovector[2*group+1]
	if start >= 0 {
		if m.subjectb != nil {
			return string(m.subjectb[start:end])
		}
		return m.subjects[start:end]
	}
	return ""
}

// Index returns the start and end of the first match, if a previous
// call to Matcher, MatcherString, Reset, ResetString, Match or
// MatchString succeeded. loc[0] is the start and loc[1] is the end.
func (m *Matcher) Index() (loc []int) {
	if !m.matches {
		return nil
	}
	loc = []int{int(m.ovector[0]), int(m.ovector[1])}
	return
}

// name2index converts a group name to its group index number.
func (m *Matcher) name2index(name string) (int, error) {
	if m.re.ptr == nil {
		return 0, fmt.Errorf("Matcher.Named: uninitialized")
	}

	return mod.substringNumberFromName(m.re, name), nil
}

// Named returns the value of the named capture group.
// This is a nil slice if the capture group is not present.
// If the name does not refer to a group then error is non-nil.
func (m *Matcher) Named(group string) ([]byte, error) {
	groupNum, err := m.name2index(group)
	if err != nil {
		return []byte{}, err
	}
	return m.Group(groupNum), nil
}

// NamedString returns the value of the named capture group,
// or an empty string if the capture group is not present.
// If the name does not refer to a group then error is non-nil.
func (m *Matcher) NamedString(group string) (string, error) {
	groupNum, err := m.name2index(group)
	if err != nil {
		return "", err
	}
	return m.GroupString(groupNum), nil
}

// NamedPresent returns true if the named capture group is present.
// If the name does not refer to a group then error is non-nil.
func (m *Matcher) NamedPresent(group string) (bool, error) {
	groupNum, err := m.name2index(group)
	if err != nil {
		return false, err
	}
	return m.Present(groupNum), nil
}

// FindIndex returns the start and end of the first match,
// or nil if no match.  loc[0] is the start and loc[1] is the end.
func (re *Regexp) FindIndex(bytes []byte, flags int) (loc []int) {
	m := re.Matcher(bytes, flags)
	if m.Matches() {
		loc = []int{int(m.ovector[0]), int(m.ovector[1])}
		return
	}
	return nil
}

// ReplaceAll returns a copy of a byte slice
// where all pattern matches are replaced by repl.
func (re Regexp) ReplaceAll(bytes, repl []byte, flags int) []byte {
	m := re.Matcher(bytes, flags)
	r := []byte{}
	for m.matches {
		r = append(append(r, bytes[:m.ovector[0]]...), repl...)
		bytes = bytes[m.ovector[1]:]
		m.Match(bytes, flags)
	}
	return append(r, bytes...)
}

// ReplaceAllString is equivalent to ReplaceAll with string return type.
func (re Regexp) ReplaceAllString(in, repl string, flags int) string {
	return string(re.ReplaceAll([]byte(in), []byte(repl), flags))
}

// CompileError holds details about a compilation error,
// as returned by the Compile function.  The offset is
// the byte position in the pattern string at which the
// error was detected.
type CompileError struct {
	Pattern string // The failed pattern
	Message string // The error message
	Offset  int    // Byte position of error
}

// Error converts a compile error to a string
func (e *CompileError) Error() string {
	return e.Pattern + " (" + strconv.Itoa(e.Offset) + "): " + e.Message
}
