// Package jsonc turns JSON with comments and trailing commas (the format of
// VS Code, Cursor and Claude settings files) into plain JSON.
package jsonc

// Strip removes // and /* */ comments and trailing commas. Newlines inside
// comments are kept so line numbers stay the same.
func Strip(src []byte) []byte {
	out := make([]byte, 0, len(src))
	inStr := false
	for i := 0; i < len(src); i++ {
		c := src[i]
		if inStr {
			out = append(out, c)
			if c == '\\' && i+1 < len(src) {
				i++
				out = append(out, src[i])
				continue
			}
			if c == '"' {
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
			out = append(out, c)
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' {
				i++
			}
			if i < len(src) {
				out = append(out, '\n')
			}
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			i += 2
			for i < len(src) && !(src[i] == '*' && i+1 < len(src) && src[i+1] == '/') {
				if src[i] == '\n' {
					out = append(out, '\n')
				}
				i++
			}
			i++ // now on the closing '/'; the loop moves past it
		default:
			out = append(out, c)
		}
	}
	return stripTrailingCommas(out)
}

func stripTrailingCommas(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inStr := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inStr {
			out = append(out, c)
			if c == '\\' && i+1 < len(b) {
				i++
				out = append(out, b[i])
				continue
			}
			if c == '"' {
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
			out = append(out, c)
			continue
		}
		if c == ',' {
			j := i + 1
			for j < len(b) && (b[j] == ' ' || b[j] == '\t' || b[j] == '\n' || b[j] == '\r') {
				j++
			}
			if j < len(b) && (b[j] == '}' || b[j] == ']') {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}
