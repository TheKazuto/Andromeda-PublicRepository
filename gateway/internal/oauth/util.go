package oauth

import "regexp"

// mustCompile is the std-lib regexp.MustCompile, re-named to keep handlers.go
// free of an extra import where it would otherwise be the only consumer.
func mustCompile(expr string) *regexp.Regexp { return regexp.MustCompile(expr) }
