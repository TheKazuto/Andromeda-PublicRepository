package policies

import "errors"

var (
	ErrUnknownTemplate     = errors.New("unknown template")
	ErrTemplateNotDeployed = errors.New("template not deployed (no program id configured)")
)
