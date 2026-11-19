# Live AWS ECS check

This check verifies real ECS ingestion, typed classification, the bounded
resource-rule authoring snapshot, and the Nitro isolation recommendation. It
does not create, modify, or delete AWS resources.

## AWS fixture

Use one ECS Managed Instances cluster in the target region with two running
tasks tagged `WorkloadType=CodingAgent`:

| Task | Trusted execution isolation mode |
| --- | --- |
| shared control | `SHARED` |
| isolated control | `ISOLATED_SANDBOX` |

Use an instance type for which `DescribeInstanceTypes` reports
`NitroEnclavesSupport=supported`. Omit `assignPublicIp` from the Managed
Instances network configuration; provide NAT or the required VPC endpoints
when the subnet has no outbound internet access. Create the fixture with the
pinned Go SDK versions in this repository rather than depending on the local
AWS CLI's ECS model.

Confirm the active identity before continuing:

```bash
aws sts get-caller-identity
```

## Run AgentShield

Run AgentShield on the host so the AWS SDK can refresh the active developer
profile. A Kind cluster can remain the Kubernetes source through the current
kubeconfig. For an in-cluster deployment outside AWS, configure IAM Roles
Anywhere through `credential_process`; do not copy an SSO session into a
Kubernetes Secret.

Create `classifiers.yaml`:

```yaml
classifiers:
  untrusted-code:
    - name: ecs-coding-agents
      match: >
        resource.kind == "aws/ecs-task" &&
        "WorkloadType" in resource.metadata.tags &&
        resource.metadata.tags["WorkloadType"] == "CodingAgent"
```

Start PostgreSQL and AgentShield, replacing the region and Kubernetes authority
as needed:

```bash
export POSTGRES_PASSWORD=agentshield
make postgres-up
export AGENTSHIELD_DATABASE_URL='postgres://agentshield:agentshield@127.0.0.1:5432/agentshield?sslmode=disable'

go run ./cmd/agentshield \
  --listen=127.0.0.1:8088 \
  --kubernetes-cluster-id=agentshield-aws-live \
  --kubernetes-source-id=kubernetes/agentshield-aws-live \
  --istio-cluster-id=agentshield-aws-live \
  --istio-source-id=kubernetes/agentshield-aws-live \
  --agentgateway-cluster-id=agentshield-aws-live \
  --agentgateway-source-id=kubernetes/agentshield-aws-live \
  --cilium-cluster-id=agentshield-aws-live \
  --cilium-source-id=kubernetes/agentshield-aws-live \
  --falco-cluster-id=agentshield-aws-live \
  --falco-source-id=kubernetes/agentshield-aws-live \
  --aws-region=us-east-1 \
  --aws-ecs \
  --aws-poll-interval=10s \
  --classifiers-file=classifiers.yaml
```

After both tasks appear in the graph, run:

```bash
curl -fsS http://127.0.0.1:8088/api/v1/graph | go run ./scripts/aws-ecs-live
```

The check passes only when both tasks publish model-authoring resource events
and the SHARED task alone receives the isolation recommendation.

Stop AgentShield, run `make postgres-down`, and clean up the AWS fixture when
finished.
