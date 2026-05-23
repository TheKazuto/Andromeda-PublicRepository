package risk

import "errors"

var (
	// ErrInvalidLevelOrder is returned when blockLevel < warnLevel.
	ErrInvalidLevelOrder = errors.New("invalid risk level order: blockLevel must be >= warnLevel")
)
