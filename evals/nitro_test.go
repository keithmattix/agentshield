package evals

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/classification"
	"github.com/agentshield-dev/agentshield/pkg/detector"
	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/remediation"
	awsplugin "github.com/agentshield-dev/agentshield/plugins/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
)

func TestNitroIsolationExperience(t *testing.T) {
	classifiers, err := classification.LoadFile("nitro-classifiers.yaml")
	if err != nil {
		t.Fatal(err)
	}
	classes, err := classifiers.Classify(context.Background(), &classification.Resource{
		Kind: "aws/ecs-task", Name: "coding-agent-a", Metadata: &classification.Metadata{Tags: map[string]string{"WorkloadType": "CodingAgent"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	projected, err := awsplugin.Project(awsplugin.ProjectionContext{Partition: "aws", Region: "us-east-1", SourceID: "aws/aws/111111111111/us-east-1"}, awsplugin.Snapshot{Tasks: []awsplugin.Task{{
		ID: "coding-agent-a", OwnerID: "111111111111", ClusterARN: "arn:aws:ecs:us-east-1:111111111111:cluster/agents",
		IsolationMode: "SHARED", Classifications: classes, EventID: "task-evidence",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	registry := graph.NewRegistry()
	if err := registry.Register(awsplugin.IdentitySchemeDefinition()); err != nil {
		t.Fatal(err)
	}
	snapshot, err := graph.NewCompiler(registry).Compile(projected.Input)
	if err != nil {
		t.Fatal(err)
	}
	signals := detector.DetectNovelChanges(graph.Snapshot{}, snapshot, time.Date(2026, time.November, 19, 12, 0, 0, 0, time.UTC), detector.DefaultConfig())
	if len(signals) != 1 || signals[0].Risk != detector.RiskHigh || !slices.Contains(signals[0].Reasons, "isolation_recommended") {
		t.Fatalf("signals = %#v", signals)
	}
	target := snapshot.Resources[0]
	suggestion := remediation.Suggestion{
		Intent: remediation.IntentWorkloadRequireIsolation, TargetEntityIDs: []string{target.ID},
		SupportingIDs: []string{signals[0].ID, "task-evidence"},
	}
	proposal, err := remediation.NewProposal("finding", "analysis", 1, suggestion, remediation.Target{EntityID: target.ID, Identity: target.Identity, Kind: target.Kind}, []string{"task-evidence"})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := awsplugin.New(awsplugin.Config{
		Partition: "aws", Region: "us-east-1", SourceID: "aws/aws/111111111111/us-east-1", EC2: evalEC2{}, ECS: evalECS{},
	})
	if err != nil {
		t.Fatal(err)
	}
	remediations, err := remediation.NewRegistry(remediation.Registration{ProviderID: "aws", SourceID: provider.SourceID(), Provider: provider})
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := remediations.Candidates(proposal)
	if err != nil || len(candidates) != 1 || candidates[0].Mode != remediation.ModeAdvisoryOnly {
		t.Fatalf("candidates = %#v, error = %v", candidates, err)
	}
	selected, action, err := remediations.Provider(proposal, candidates[0].ProviderID, candidates[0].SourceID, candidates[0].ActionID)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := selected.Plan(context.Background(), proposal, action.ID)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Mode != remediation.ModeAdvisoryOnly || plan.Advisory == "" {
		t.Fatalf("plan = %#v", plan)
	}
}

type evalEC2 struct{}

func (evalEC2) DescribeNetworkInterfaces(context.Context, *ec2.DescribeNetworkInterfacesInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	return &ec2.DescribeNetworkInterfacesOutput{}, nil
}

func (evalEC2) DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	return &ec2.DescribeInstancesOutput{}, nil
}

func (evalEC2) DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	return &ec2.DescribeSecurityGroupsOutput{}, nil
}

type evalECS struct{}

func (evalECS) ListClusters(context.Context, *ecs.ListClustersInput, ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
	return &ecs.ListClustersOutput{}, nil
}

func (evalECS) ListTasks(context.Context, *ecs.ListTasksInput, ...func(*ecs.Options)) (*ecs.ListTasksOutput, error) {
	return &ecs.ListTasksOutput{}, nil
}

func (evalECS) DescribeTasks(context.Context, *ecs.DescribeTasksInput, ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error) {
	return &ecs.DescribeTasksOutput{}, nil
}
