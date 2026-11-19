package classification

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/google/cel-go/cel"
	"sigs.k8s.io/yaml"
)

const (
	UntrustedCode   = "untrusted-code"
	SensitiveData   = "sensitive-data"
	AttributePrefix = "agentshield/classification/"
)

type Rule struct {
	Name  string `json:"name"`
	Match string `json:"match"`
}

type Config struct {
	Classifiers map[string][]Rule `json:"classifiers"`
}

type Engine struct {
	classifiers map[string][]cel.Program
}

func LoadFile(path string) (*Engine, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read classifiers: %w", err)
	}
	var config Config
	if err := yaml.UnmarshalStrict(content, &config); err != nil {
		return nil, fmt.Errorf("decode classifiers: %w", err)
	}
	return New(config)
}

func New(config Config) (*Engine, error) {
	environment, err := cel.NewEnv(
		cel.Types(&Resource{}, &Metadata{}),
		cel.Variable("resource", cel.ObjectType("agentshield.classification.v1.Resource")),
	)
	if err != nil {
		return nil, err
	}
	engine := &Engine{classifiers: make(map[string][]cel.Program, len(config.Classifiers))}
	for classification, rules := range config.Classifiers {
		if classification != UntrustedCode && classification != SensitiveData {
			return nil, fmt.Errorf("unsupported classification %q", classification)
		}
		if len(rules) == 0 {
			return nil, fmt.Errorf("classification %q requires at least one rule", classification)
		}
		seen := map[string]bool{}
		for _, rule := range rules {
			if strings.TrimSpace(rule.Name) == "" || strings.TrimSpace(rule.Name) != rule.Name || len(rule.Name) > 128 || seen[rule.Name] {
				return nil, fmt.Errorf("classification %q has invalid or duplicate rule name %q", classification, rule.Name)
			}
			if len(rule.Match) == 0 || len(rule.Match) > 8192 {
				return nil, fmt.Errorf("classification %q rule %q requires a 1-8192 byte expression", classification, rule.Name)
			}
			seen[rule.Name] = true
			ast, issues := environment.Compile(rule.Match)
			if issues.Err() != nil {
				return nil, fmt.Errorf("compile classification %q rule %q: %w", classification, rule.Name, issues.Err())
			}
			if !ast.OutputType().IsExactType(cel.BoolType) {
				return nil, fmt.Errorf("compile classification %q rule %q: expression must return bool, got %s", classification, rule.Name, ast.OutputType())
			}
			program, err := environment.Program(ast, cel.CostLimit(10_000), cel.InterruptCheckFrequency(100))
			if err != nil {
				return nil, fmt.Errorf("compile classification %q rule %q: %w", classification, rule.Name, err)
			}
			engine.classifiers[classification] = append(engine.classifiers[classification], program)
		}
	}
	return engine, nil
}

func (engine *Engine) Classify(ctx context.Context, resource *Resource) ([]string, error) {
	if engine == nil {
		return nil, nil
	}
	if resource == nil {
		return nil, errors.New("classification resource is required")
	}
	var result []string
	for classification, rules := range engine.classifiers {
		for _, rule := range rules {
			value, _, err := rule.ContextEval(ctx, map[string]any{"resource": resource})
			if err != nil {
				return nil, fmt.Errorf("evaluate classification %q: %w", classification, err)
			}
			matched, ok := value.Value().(bool)
			if !ok {
				return nil, fmt.Errorf("evaluate classification %q returned %T", classification, value.Value())
			}
			if matched {
				result = append(result, classification)
				break
			}
		}
	}
	slices.Sort(result)
	return result, nil
}
