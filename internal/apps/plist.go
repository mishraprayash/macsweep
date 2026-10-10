package apps

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"os"
	"os/exec"
)

// plistValues holds a plist's top-level string and string-array values.
type plistValues map[string][]string

// first returns the first value of key, or "".
func (v plistValues) first(key string) string {
	if len(v[key]) == 0 {
		return ""
	}
	return v[key][0]
}

// readPlist reads the top-level string and string-array values of a plist
// file. Binary plists are converted with plutil; XML is parsed here.
func readPlist(path string) plistValues {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	if !bytes.HasPrefix(data, []byte("bplist")) {
		return parseXMLPlist(data)
	}
	out, err := exec.Command("plutil", "-convert", "json", "-o", "-", path).Output()
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(out, &m) != nil {
		return nil
	}
	v := plistValues{}
	for k, val := range m {
		switch t := val.(type) {
		case string:
			v[k] = []string{t}
		case []any:
			for _, e := range t {
				if s, ok := e.(string); ok {
					v[k] = append(v[k], s)
				}
			}
		}
	}
	return v
}

// parseXMLPlist reads the top-level <key>K</key> followed by <string> or an
// <array> of <string> from an XML plist. Nested dicts are skipped.
func parseXMLPlist(data []byte) plistValues {
	v := plistValues{}
	dec := xml.NewDecoder(bytes.NewReader(data))
	depth, key := 0, "" // depth 1 is the top-level dict
	inArray := false
	for {
		tok, err := dec.Token()
		if err != nil { // io.EOF at the end
			return v
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch name := t.Name.Local; {
			case name == "dict":
				depth++
			case name == "array":
				if depth == 1 && key != "" && !inArray {
					inArray = true
					continue
				}
				depth++
			case depth == 1:
				var text string
				if err := dec.DecodeElement(&text, &t); err != nil {
					return v
				}
				switch {
				case name == "key" && !inArray:
					key = text
				case name == "string" && key != "":
					v[key] = append(v[key], text)
					if !inArray {
						key = ""
					}
				case !inArray:
					key = ""
				}
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "dict":
				depth--
				key = ""
			case "array":
				if inArray && depth == 1 {
					inArray, key = false, ""
				} else {
					depth--
				}
			}
		}
	}
}
