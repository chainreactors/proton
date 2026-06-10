package file

// compiledRegexp abstracts regexp so we can swap wasilibs/go-re2 (Go 1.22+)
// with stdlib regexp (Go <1.22) via build tags.
type compiledRegexp interface {
	MatchString(s string) bool
	FindAllString(s string, n int) []string
	FindAllStringSubmatch(s string, n int) [][]string
}
