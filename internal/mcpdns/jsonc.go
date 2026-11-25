package mcpdns

// OpenCode accepts JSONC. Blank comments and trailing commas outside strings,
// retaining token boundaries so the ordinary JSON decoder still rejects malformed input.
func cleanJSONC(input []byte) []byte {
	b := append([]byte(nil), input...)
	var quoted, escaped bool
	last := -1
	for i := 0; i < len(b); i++ {
		c := b[i]
		if quoted {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
			} else if c == '"' {
				quoted = false
			}
			continue
		}
		switch c {
		case '"':
			quoted = true
		case ' ', '\n', '\r', '\t':
			continue
		case '/':
			if i+1 >= len(b) {
				return nil
			}
			switch b[i+1] {
			case '/':
				for i < len(b) && b[i] != '\n' && b[i] != '\r' {
					b[i] = ' '
					i++
				}
				i--
			case '*':
				b[i], b[i+1] = ' ', ' '
				i += 2
				for i+1 < len(b) && (b[i] != '*' || b[i+1] != '/') {
					b[i] = ' '
					i++
				}
				if i+1 >= len(b) {
					return nil
				}
				b[i], b[i+1] = ' ', ' '
				i++
			default:
				return nil
			}
			continue
		case '}', ']':
			if last >= 0 && b[last] == ',' {
				b[last] = ' '
			}
		}
		last = i
	}
	return b
}
