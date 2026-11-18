package aws

import (
	"context"
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	awsdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

func TestCaptureECSTasksWithNitroSandbox(t *testing.T) {
	tasks, err := captureTasks(context.Background(), fakeECS{}, "aws", "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 1 {
		t.Fatalf("tasks = %#v", tasks)
	}
	got := tasks[0]
	if got.ID != "task-1" || got.OwnerID != "111111111111" || got.IsolationMode != "CONFIDENTIAL_SANDBOX" || got.AttestationPolicyStatus != "CONFIGURED" {
		t.Fatalf("task = %#v", got)
	}
	if len(got.NetworkInterfaceIDs) != 1 || got.NetworkInterfaceIDs[0] != "eni-1" || got.Revision == "" || got.EventID == "" {
		t.Fatalf("task delivery fields = %#v", got)
	}
}

func TestProjectECSTaskTopologyAndIsolation(t *testing.T) {
	result, err := Project(ProjectionContext{Partition: "aws", Region: "us-east-1", SourceID: "source"}, Snapshot{
		NetworkInterfaces: []NetworkInterface{{ID: "eni-1", OwnerID: "111111111111", EventID: "eni-event"}},
		Tasks: []Task{{
			ID: "task-1", OwnerID: "111111111111", ClusterARN: "arn:aws:ecs:us-east-1:111111111111:cluster/agents",
			NetworkInterfaceIDs: []string{"eni-1"}, IsolationMode: "CONFIDENTIAL_SANDBOX",
			AttestationPolicyStatus: "CONFIGURED", EventID: "task-event",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	resource := resourceByKind(t, result.Input, "aws/ecs-task")
	if resource.Attributes["aws/ecs-isolation-mode"] != "CONFIDENTIAL_SANDBOX" || resource.Attributes["aws/ecs-attestation-policy-status"] != "CONFIGURED" {
		t.Fatalf("task attributes = %#v", resource.Attributes)
	}
	if len(result.Input.Relationships) != 1 || result.Input.Relationships[0].Predicate != graph.PredicateBackedBy || result.Input.Relationships[0].Object.ImmutableKey != "aws/ec2/us-east-1/network-interface/eni-1" {
		t.Fatalf("task relationships = %#v", result.Input.Relationships)
	}
	compileCanonical(t, result.Input)
}

func TestProjectECSFargateTaskIsolation(t *testing.T) {
	result, err := Project(ProjectionContext{Partition: "aws", Region: "us-east-1", SourceID: "source"}, Snapshot{Tasks: []Task{{
		ID: "task-1", OwnerID: "111111111111", ClusterARN: "arn:aws:ecs:us-east-1:111111111111:cluster/agents",
		CapacityProviderName: "FARGATE_SPOT", EventID: "task-event",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	attributes := resourceByKind(t, result.Input, "aws/ecs-task").Attributes
	if attributes["aws/ecs-capacity-provider"] != "FARGATE_SPOT" || attributes["aws/ecs-isolation-boundary"] != "task" {
		t.Fatalf("task attributes = %#v", attributes)
	}
}

type fakeECS struct{}

func (fakeECS) ListClusters(context.Context, *ecs.ListClustersInput, ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
	return &ecs.ListClustersOutput{ClusterArns: []string{"arn:aws:ecs:us-east-1:111111111111:cluster/agents"}}, nil
}

func (fakeECS) ListTasks(_ context.Context, input *ecs.ListTasksInput, _ ...func(*ecs.Options)) (*ecs.ListTasksOutput, error) {
	if input.DesiredStatus != ecstypes.DesiredStatusRunning {
		return nil, nil
	}
	return &ecs.ListTasksOutput{TaskArns: []string{"arn:aws:ecs:us-east-1:111111111111:task/agents/task-1"}}, nil
}

func (fakeECS) DescribeTasks(context.Context, *ecs.DescribeTasksInput, ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error) {
	return &ecs.DescribeTasksOutput{Tasks: []ecstypes.Task{{
		TaskArn:    awsdk.String("arn:aws:ecs:us-east-1:111111111111:task/agents/task-1"),
		ClusterArn: awsdk.String("arn:aws:ecs:us-east-1:111111111111:cluster/agents"),
		Attachments: []ecstypes.Attachment{{Type: awsdk.String("ElasticNetworkInterface"), Details: []ecstypes.KeyValuePair{{
			Name: awsdk.String("networkInterfaceId"), Value: awsdk.String("eni-1"),
		}}}},
		TrustedExecutionSummary: &ecstypes.TrustedExecutionSummary{
			IsolationMode: ecstypes.IsolationModeConfidentialSandbox, AttestationPolicyStatus: ecstypes.AttestationPolicyStatusConfigured,
		},
	}}}, nil
}
