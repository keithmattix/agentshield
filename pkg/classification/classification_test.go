package classification

import (
	"context"
	"reflect"
	"testing"
)

func TestClassifiersAreTypedAndORRules(t *testing.T) {
	engine, err := New(Config{Classifiers: map[string][]Rule{
		UntrustedCode: {
			{Name: "kubernetes-build-workers", Match: `resource.kind == "kubernetes/deployment" && resource.metadata.labels["workload.example.com/type"] == "build-worker"`},
			{Name: "ecs-coding-agents", Match: `resource.kind == "aws/ecs-task" && resource.metadata.tags["WorkloadType"] == "CodingAgent"`},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := engine.Classify(context.Background(), &Resource{Kind: "aws/ecs-task", Metadata: &Metadata{Tags: map[string]string{"WorkloadType": "CodingAgent"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{UntrustedCode}) {
		t.Fatalf("classifications = %v", got)
	}
}

func TestClassifierRejectsUnknownResourceField(t *testing.T) {
	_, err := New(Config{Classifiers: map[string][]Rule{UntrustedCode: {{Name: "typo", Match: `resource.tags["WorkloadType"] == "CodingAgent"`}}}})
	if err == nil {
		t.Fatal("New() succeeded")
	}
}
