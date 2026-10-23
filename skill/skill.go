// Package skill embeds the triage method, which is also usable as an Agent Skill on its own.
package skill

import _ "embed"

// Text is the method of the reader, which sees the report.
//
//go:embed SKILL.md
var Text string

// Compare is the method of the comparator, which looks for duplicates without seeing the report.
//
//go:embed compare.md
var Compare string
