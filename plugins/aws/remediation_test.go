package aws

import (
	"context"
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/remediation"
)

func TestNitroIsolationAdvisory(t *testing.T) {
	plugin, err := New(Config{Partition: "aws", Region: "us-east-1", SourceID: "aws/aws/111111111111/us-east-1", EC2: &failingEC2{}, ECS: fakeECS{}})
	if err != nil {
		t.Fatal(err)
	}
	suggestion := remediation.Suggestion{Intent: remediation.IntentWorkloadRequireIsolation, TargetEntityIDs: []string{"target"}, SupportingIDs: []string{"evidence"}}
	proposal, err := remediation.NewProposal("finding", "analysis", 1, suggestion, remediation.Target{
		EntityID: "target", Kind: "aws/ecs-task", Identity: taskClaim(ProjectionContext{Partition: "aws", Region: "us-east-1"}, Task{ID: "task-1", OwnerID: "111111111111"}),
	}, []string{"evidence"})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := plugin.Plan(context.Background(), proposal, nitroIsolationActionID)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Mode != remediation.ModeAdvisoryOnly || plan.Advisory == "" {
		t.Fatalf("plan = %#v", plan)
	}
}
