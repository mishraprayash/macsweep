package rules

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"

	"gopkg.in/yaml.v3"
)

//go:embed builtin/*.yaml
var builtinFS embed.FS

// Builtin returns the embedded rules, in file then definition order.
func Builtin() ([]*Rule, error) {
	files, err := fs.Glob(builtinFS, "builtin/*.yaml")
	if err != nil {
		return nil, err
	}
	var out []*Rule
	for _, f := range files {
		data, err := builtinFS.ReadFile(f)
		if err != nil {
			return nil, err
		}
		rs, err := parseRules(data, f, false)
		if err != nil {
			return nil, err
		}
		out = append(out, rs...)
	}
	return out, nil
}

func parseRules(data []byte, source string, user bool) ([]*Rule, error) {
	var rs []*Rule
	if err := decodeStrict(data, &rs); err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	for _, r := range rs {
		if r == nil {
			return nil, fmt.Errorf("%s: empty rule entry", source)
		}
		r.Source, r.User = source, user
	}
	return rs, nil
}

func decodeStrict(data []byte, v any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// UserConfig is the user's rules file (~/.config/sweep/rules.yaml):
//
//	rules:      # extra rules, same schema as the built-in ones
//	  - id: my-build-cache
//	    ...
//	exclude:    # paths/globs that clean must never touch
//	  - ~/code/keep-this/**
type UserConfig struct {
	Rules   []*Rule  `yaml:"rules"`
	Exclude []string `yaml:"exclude"`
}

// DefaultUserConfigPath is where user rules live by default.
func DefaultUserConfigPath(home string) string {
	return path.Join(home, ".config", "sweep", "rules.yaml")
}

// LoadUserConfig reads a user rules file. A missing file is not an error
// unless required is set (the user passed --config explicitly).
func LoadUserConfig(file string, required bool) (*UserConfig, error) {
	data, err := os.ReadFile(file)
	if errors.Is(err, fs.ErrNotExist) && !required {
		return &UserConfig{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	var cfg UserConfig
	if err := decodeStrict(data, &cfg); err != nil {
		return nil, fmt.Errorf("config %s: %w", file, err)
	}
	for i, r := range cfg.Rules {
		if r == nil {
			return nil, fmt.Errorf("config %s: rule %d is empty", file, i+1)
		}
		r.Source, r.User = file, true
	}
	return &cfg, nil
}
