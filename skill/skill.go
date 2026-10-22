// Package skill embeds the triage method, which is also usable as an Agent Skill on its own.
package skill

import _ "embed"

//go:embed SKILL.md
var Text string
