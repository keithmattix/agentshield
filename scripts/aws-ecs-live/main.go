package main

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/classification"
	"github.com/agentshield-dev/agentshield/pkg/detector"
	"github.com/agentshield-dev/agentshield/pkg/graph"
)

func main() {
	var response struct {
		Snapshot graph.Snapshot `json:"snapshot"`
	}
	if err := json.NewDecoder(os.Stdin).Decode(&response); err != nil {
		fail(fmt.Errorf("decode graph response: %w", err))
	}
	resources := map[string]string{}
	for _, resource := range response.Snapshot.Resources {
		if resource.Kind != "aws/ecs-task" {
			continue
		}
		for _, assertion := range resource.Assertions {
			context, err := graph.DecodeResourceAuthoringContext(assertion.Attributes[graph.ResourceAuthoringContextAttribute])
			if err != nil {
				continue
			}
			if context.Attributes[classification.AttributePrefix+classification.UntrustedCode] != "true" {
				fail(fmt.Errorf("ECS task %s is not classified untrusted-code", resource.ID))
			}
			mode := context.Attributes["aws/ecs-isolation-mode"]
			if mode != "SHARED" && mode != "ISOLATED_SANDBOX" {
				fail(fmt.Errorf("ECS task %s has unexpected isolation mode %q", resource.ID, mode))
			}
			resources[resource.ID] = mode
		}
	}
	if !containsValue(resources, "SHARED") || !containsValue(resources, "ISOLATED_SANDBOX") {
		fail(fmt.Errorf("want SHARED and ISOLATED_SANDBOX authoring contexts, got %v", resources))
	}
	var isolationAnchors []string
	for _, signal := range detector.DetectNovelChanges(graph.Snapshot{}, response.Snapshot, time.Now(), detector.DefaultConfig()) {
		if slices.Contains(signal.Reasons, "isolation_recommended") {
			isolationAnchors = append(isolationAnchors, signal.AnchorIDs...)
		}
	}
	if len(isolationAnchors) == 0 {
		fail(fmt.Errorf("want an isolation recommendation for a SHARED task, got none"))
	}
	for _, anchor := range isolationAnchors {
		if resources[anchor] != "SHARED" {
			fail(fmt.Errorf("isolation recommendation targets non-SHARED task %s", anchor))
		}
	}
	fmt.Printf("PASS: %d SHARED task(s) recommended for isolation; ISOLATED_SANDBOX tasks were not\n", len(isolationAnchors))
}

func containsValue(values map[string]string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
