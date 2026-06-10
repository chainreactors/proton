package file

// compiledRegexp abstracts regexp so we can swap wasilibs/go-re2 (Go 1.22+)
// with stdlib regexp (Go <1.22) via build tags.
type compiledRegexp interface {
	Match(b []byte) bool
	MatchString(s string) bool
	FindAll(b []byte, n int) [][]byte
	FindAllIndex(b []byte, n int) [][]int
	FindAllSubmatch(b []byte, n int) [][][]byte
	FindAllString(s string, n int) []string
	FindAllStringIndex(s string, n int) [][]int
	FindAllStringSubmatch(s string, n int) [][]string
}
