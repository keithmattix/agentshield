// Package aws is a regional AWS source plugin for EC2 instances, elastic
// network interfaces, security groups, and optional ECS tasks, with optional
// VPC Flow Log ingestion from Amazon Data Firehose.
//
// # Source and collections
//
// The plugin polls EC2 Describe APIs with full pagination at startup, every
// poll interval, and immediately when an optional SQS subscriber reports a
// matching CloudTrail change. Polling, not the event stream, is authoritative:
// events only trigger a current-state read, so duplicates and reordering are
// harmless. Each object is content-digested so retries keep stable event IDs,
// and the plugin publishes the aws/ec2/<region>/network-interfaces, instances,
// security-groups, and optional aws/ecs/<region>/tasks collections. ECS task
// observations include Nitro Sandbox isolation and attestation-policy status.
//
// # Identity
//
// Resources use the aws.amazon.com/v1 Resource scheme. The authority is each
// resource's 12-digit owner account, not the caller account, so shared-VPC
// resources owned by another account keep their owner's identity. Immutable
// keys are <partition>/<service>/<region>/<type>/<id>. The source ID
// aws/<partition>/<caller-account>/<region> identifies the observer only.
// [Plugin.ResolveIdentityReference] turns a Kubernetes Node's aws:// provider
// ID into an instance claim so Kubernetes can assert Node backed-by instance.
//
// # Graph output and failure behavior
//
// The "inventory" contribution asserts instances, network interfaces, security
// groups, and ECS tasks, network interface governed-by security group, ECS task
// backed-by network interface, and network interface exposes network destination
// for its current addresses, with an aws-security-group-rules facet carrying
// typed security semantics. Nitro isolation remains provider-native because the
// graph security vocabulary has no workload-isolation or attestation domain.
// An initial API failure prevents readiness. After a coherent publication, a failed poll
// republishes the last coherent input once with degraded health; recovery
// restores healthy status.
//
// # Telemetry
//
// [Plugin.FirehoseHandler] authenticates Firehose HTTP endpoint deliveries for
// one stream and access key and decodes VPC Flow Log records with
// [NormalizeVPCFlowLog]. It acknowledges a delivery only after every event is
// accepted into the shared pipeline's bounded queue. A full queue blocks the
// delivery as backpressure, and a delivery abandoned while blocked returns 503
// so Firehose retries. Raw events reach the sink before any graph rollup.
//
// See https://agent-shield.dev/docs/plugins/aws/.
package aws
