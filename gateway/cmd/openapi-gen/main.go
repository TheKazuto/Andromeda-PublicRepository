// Command openapi-gen renders the gateway's OpenAPI 3.1 document to a YAML file
// (default: openapi.yaml in the current directory). Run from the gateway module
// root so the file lands at gateway/openapi.yaml:
//
//	cd gateway && go run ./cmd/openapi-gen
//
// The committed YAML is a derivative of internal/openapi (Generator + extras +
// routes.All). A guard test keeps it from drifting from the generator.
package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/shinkalabs/andromeda-gateway/internal/openapi"
)

func main() {
	out, err := openapi.SnapshotYAML()
	if err != nil {
		log.Fatalf("openapi-gen: %v", err)
	}
	dest := "openapi.yaml"
	if len(os.Args) > 1 {
		dest = os.Args[1]
	}
	if err := os.WriteFile(dest, out, 0o644); err != nil {
		log.Fatalf("openapi-gen: write %s: %v", filepath.Clean(dest), err)
	}
	log.Printf("openapi-gen: wrote %s (%d bytes)", dest, len(out))
}
