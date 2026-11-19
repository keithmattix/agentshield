package aws

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/classification"
	awsdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

// ECSAPI is the subset of the ECS client used for task inventory.
type ECSAPI interface {
	ListClusters(context.Context, *ecs.ListClustersInput, ...func(*ecs.Options)) (*ecs.ListClustersOutput, error)
	ListTasks(context.Context, *ecs.ListTasksInput, ...func(*ecs.Options)) (*ecs.ListTasksOutput, error)
	DescribeTasks(context.Context, *ecs.DescribeTasksInput, ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error)
}

func captureTasks(ctx context.Context, client ECSAPI, classifiers *classification.Engine, partition, region string) ([]Task, error) {
	if client == nil {
		return nil, nil
	}
	clusters := ecs.NewListClustersPaginator(client, &ecs.ListClustersInput{MaxResults: awsdk.Int32(100)})
	var result []Task
	for clusters.HasMorePages() {
		page, err := nextECSPage(ctx, clusters.NextPage)
		if err != nil {
			return nil, fmt.Errorf("list ECS clusters in %s: %w", region, err)
		}
		for _, clusterARN := range page.ClusterArns {
			tasks := ecs.NewListTasksPaginator(client, &ecs.ListTasksInput{
				Cluster: &clusterARN, DesiredStatus: types.DesiredStatusRunning, MaxResults: awsdk.Int32(100),
			})
			for tasks.HasMorePages() {
				taskPage, err := nextECSPage(ctx, tasks.NextPage)
				if err != nil {
					return nil, fmt.Errorf("list ECS tasks in cluster %s: %w", clusterARN, err)
				}
				for start := 0; start < len(taskPage.TaskArns); start += 100 {
					end := min(start+100, len(taskPage.TaskArns))
					output, err := nextECSPage(ctx, func(ctx context.Context, options ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error) {
						input := &ecs.DescribeTasksInput{Cluster: &clusterARN, Tasks: taskPage.TaskArns[start:end]}
						if classifiers != nil {
							input.Include = []types.TaskField{types.TaskFieldTags}
						}
						return client.DescribeTasks(ctx, input, options...)
					})
					if err != nil {
						return nil, fmt.Errorf("describe ECS tasks in cluster %s: %w", clusterARN, err)
					}
					if len(output.Failures) > 0 {
						return nil, fmt.Errorf("describe ECS tasks in cluster %s returned %d failures", clusterARN, len(output.Failures))
					}
					for _, value := range output.Tasks {
						item, err := normalizeTask(ctx, value, classifiers, partition, region)
						if err != nil {
							return nil, err
						}
						result = append(result, item)
					}
				}
			}
		}
	}
	slices.SortFunc(result, func(left, right Task) int { return strings.Compare(left.ID, right.ID) })
	return result, nil
}

func nextECSPage[T any](ctx context.Context, fetch func(context.Context, ...func(*ecs.Options)) (T, error)) (T, error) {
	ctx, cancel := context.WithTimeout(ctx, describeTimeout)
	defer cancel()
	return fetch(ctx)
}

func normalizeTask(ctx context.Context, value types.Task, classifiers *classification.Engine, partition, region string) (Task, error) {
	taskARN := strings.TrimSpace(awsdk.ToString(value.TaskArn))
	parsed, err := arn.Parse(taskARN)
	if err != nil || parsed.Partition != partition || parsed.Service != "ecs" || parsed.Region != region || !validAccountID(parsed.AccountID) {
		return Task{}, fmt.Errorf("ECS task in %s has invalid ARN %q", region, taskARN)
	}
	id := parsed.Resource[strings.LastIndex(parsed.Resource, "/")+1:]
	item := Task{
		ID: id, OwnerID: parsed.AccountID, ClusterARN: strings.TrimSpace(awsdk.ToString(value.ClusterArn)),
		TaskDefinitionARN: awsdk.ToString(value.TaskDefinitionArn), ContainerInstanceARN: awsdk.ToString(value.ContainerInstanceArn),
		AvailabilityZone: awsdk.ToString(value.AvailabilityZone), CapacityProviderName: awsdk.ToString(value.CapacityProviderName),
		LaunchType: string(value.LaunchType), DesiredStatus: awsdk.ToString(value.DesiredStatus), LastStatus: awsdk.ToString(value.LastStatus),
		HealthStatus: string(value.HealthStatus), Version: value.Version,
	}
	for _, attachment := range value.Attachments {
		if !strings.EqualFold(awsdk.ToString(attachment.Type), "ElasticNetworkInterface") {
			continue
		}
		for _, detail := range attachment.Details {
			if strings.EqualFold(awsdk.ToString(detail.Name), "networkInterfaceId") {
				item.NetworkInterfaceIDs = appendNonempty(item.NetworkInterfaceIDs, awsdk.ToString(detail.Value))
			}
		}
	}
	item.NetworkInterfaceIDs = uniqueSorted(item.NetworkInterfaceIDs)
	if value.TrustedExecutionSummary != nil {
		item.IsolationMode = string(value.TrustedExecutionSummary.IsolationMode)
		item.AttestationPolicyStatus = string(value.TrustedExecutionSummary.AttestationPolicyStatus)
	}
	if strings.TrimSpace(item.ID) == "" || strings.TrimSpace(item.ClusterARN) == "" {
		return Task{}, fmt.Errorf("ECS task in %s requires task and cluster ARNs", region)
	}
	tags := make(map[string]string, len(value.Tags))
	for _, tag := range value.Tags {
		if key := strings.TrimSpace(awsdk.ToString(tag.Key)); key != "" {
			tags[key] = awsdk.ToString(tag.Value)
		}
	}
	item.Classifications, err = classifiers.Classify(ctx, &classification.Resource{
		Kind: "aws/ecs-task", Name: item.ID, Namespace: item.ClusterARN,
		Metadata: &classification.Metadata{Tags: tags},
	})
	if err != nil {
		return Task{}, fmt.Errorf("classify ECS task %s: %w", item.ID, err)
	}
	revision, err := contentRevision(item)
	if err != nil {
		return Task{}, err
	}
	item.Revision = revision
	item.EventID = eventID(tasksCollection(region), item.ID, revision, "upsert")
	return item, nil
}
