package modelproxy

import "slices"

// Validate protocol positions, not arbitrary JSON in function schemas or tool arguments.
// A new provider capability must be reviewed before it can cross this boundary.
func safeRequest(v map[string]any, anthropic bool) bool {
	if anthropic {
		return fields(v, "model", "messages", "system", "tools", "tool_choice", "max_tokens", "stream", "temperature", "top_p", "top_k", "stop_sequences", "thinking", "output_config", "metadata", "cache_control", "context_management") &&
			safeMessages(v["messages"]) && safeContent(v["system"], true) && safeToolList(v["tools"], true) && safeContextEdits(v["context_management"])
	}
	if !fields(v, "model", "input", "instructions", "tools", "tool_choice", "parallel_tool_calls", "reasoning", "store", "stream", "stream_options", "include", "text", "max_output_tokens", "max_tokens", "metadata", "client_metadata", "prompt_cache_key", "service_tier", "background") {
		return false
	}
	if background, ok := v["background"]; ok && background != false {
		return false
	}
	if include, ok := v["include"]; ok {
		values, ok := include.([]any)
		if !ok {
			return false
		}
		for _, value := range values {
			if value != "reasoning.encrypted_content" {
				return false
			}
		}
	}
	return safeItems(v["input"]) && safeToolList(v["tools"], false) && safeToolChoice(v["tool_choice"])
}

func fields(v map[string]any, allowed ...string) bool {
	for key := range v {
		if !slices.Contains(allowed, key) {
			return false
		}
	}
	return true
}

func safeToolList(v any, anthropic bool) bool {
	if v == nil {
		return true
	}
	list, ok := v.([]any)
	if !ok {
		return false
	}
	for _, item := range list {
		t, ok := item.(map[string]any)
		if !ok {
			return false
		}
		if anthropic {
			if !fields(t, "name", "description", "input_schema", "cache_control", "type", "strict", "defer_loading") || (t["type"] != nil && t["type"] != "custom") {
				return false
			}
			continue
		}
		switch t["type"] {
		case "function":
			if !fields(t, "type", "name", "description", "parameters", "strict", "defer_loading") {
				return false
			}
		case "custom":
			if !fields(t, "type", "name", "description", "format", "defer_loading") {
				return false
			}
		case "namespace":
			if !fields(t, "type", "name", "description", "tools") || !safeToolList(t["tools"], false) {
				return false
			}
		case "local_shell", "apply_patch":
			if !fields(t, "type") {
				return false
			}
		case "tool_search":
			if t["execution"] != "client" || !fields(t, "type", "execution", "description", "parameters") {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func safeToolChoice(v any) bool {
	if v == nil || v == "auto" || v == "none" || v == "required" {
		return true
	}
	t, ok := v.(map[string]any)
	return ok && (t["type"] == "function" || t["type"] == "custom") && fields(t, "type", "name")
}

func safeItems(v any) bool {
	if v == nil {
		return true
	}
	if _, ok := v.(string); ok {
		return true
	}
	items, ok := v.([]any)
	if !ok {
		return false
	}
	for _, item := range items {
		t, ok := item.(map[string]any)
		if !ok {
			return false
		}
		switch t["type"] {
		case nil, "message":
			if (t["type"] == nil && t["id"] != nil) || !fields(t, "type", "id", "role", "content", "status", "phase") || !safeContent(t["content"], false) {
				return false
			}
		case "reasoning":
			if !fields(t, "type", "id", "summary", "content", "encrypted_content", "status") {
				return false
			}
		case "function_call", "custom_tool_call":
			if !fields(t, "type", "id", "call_id", "name", "arguments", "input", "status", "namespace") {
				return false
			}
		case "function_call_output", "custom_tool_call_output":
			if !fields(t, "type", "id", "call_id", "output", "status") || !safeContent(t["output"], false) {
				return false
			}
		case "additional_tools", "tool_search_output":
			if !fields(t, "type", "id", "call_id", "role", "tools", "status", "execution") || !safeToolList(t["tools"], false) {
				return false
			}
		case "tool_search_call":
			if t["execution"] != "client" || !fields(t, "type", "id", "call_id", "arguments", "status", "execution") {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func safeMessages(v any) bool {
	if v == nil {
		return true
	}
	items, ok := v.([]any)
	if !ok {
		return false
	}
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok || !fields(m, "role", "content", "output_config") || !safeContent(m["content"], true) {
			return false
		}
		if output, ok := m["output_config"]; ok {
			config, ok := output.(map[string]any)
			if !ok || !fields(config, "effort") {
				return false
			}
		}
	}
	return true
}

func safeContent(v any, anthropic bool) bool {
	if v == nil {
		return true
	}
	if _, ok := v.(string); ok {
		return true
	}
	list, ok := v.([]any)
	if !ok {
		return false
	}
	for _, item := range list {
		t, ok := item.(map[string]any)
		if !ok {
			return false
		}
		if !anthropic {
			if !slices.Contains([]any{"input_text", "output_text", "refusal"}, t["type"]) || !fields(t, "type", "text", "refusal", "annotations") {
				return false
			}
			continue
		}
		switch t["type"] {
		case "text":
			if !fields(t, "type", "text", "cache_control") {
				return false
			}
		case "thinking", "redacted_thinking":
			if !fields(t, "type", "thinking", "signature", "data") {
				return false
			}
		case "tool_use":
			if !fields(t, "type", "id", "name", "input", "cache_control") {
				return false
			}
		case "tool_result":
			if !fields(t, "type", "tool_use_id", "content", "is_error", "cache_control") || !safeContent(t["content"], true) {
				return false
			}
		case "tool_reference":
			if !fields(t, "type", "tool_name") {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func safeContextEdits(v any) bool {
	if v == nil {
		return true
	}
	m, ok := v.(map[string]any)
	if !ok || !fields(m, "edits") {
		return false
	}
	edits, ok := m["edits"].([]any)
	if !ok {
		return false
	}
	for _, edit := range edits {
		e, ok := edit.(map[string]any)
		if !ok {
			return false
		}
		switch e["type"] {
		case "clear_thinking_20251015":
			if !fields(e, "type", "keep") {
				return false
			}
		case "clear_tool_uses_20250919":
			if !fields(e, "type", "trigger", "keep", "clear_at_least", "exclude_tools", "clear_tool_inputs") {
				return false
			}
		default:
			return false
		}
	}
	return true
}
