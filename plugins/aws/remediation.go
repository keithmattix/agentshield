package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/remediation"
)

const nitroIsolationActionID = "ecs-nitro-isolated-sandbox/v1"

func (p *Plugin) RemediationDescriptor() remediation.Descriptor {
	if p.config.ECS == nil {
		return remediation.Descriptor{}
	}
	parts := strings.Split(p.config.SourceID, "/")
	if len(parts) != 4 {
		return remediation.Descriptor{}
	}
	return remediation.Descriptor{Actions: []remediation.Action{{
		ID: nitroIsolationActionID, Intent: remediation.IntentWorkloadRequireIsolation, TargetKind: "aws/ecs-task",
		Scheme: resourceScheme, AuthorityID: parts[2], Mode: remediation.ModeAdvisoryOnly,
	}}}
}

func (p *Plugin) Plan(_ context.Context, proposal remediation.Proposal, actionID string) (remediation.Plan, error) {
	if actionID != nitroIsolationActionID {
		return remediation.Plan{}, fmt.Errorf("unsupported AWS remediation action %q", actionID)
	}
	parts := strings.Split(p.config.SourceID, "/")
	if len(parts) != 4 || proposal.Intent != remediation.IntentWorkloadRequireIsolation || proposal.Target.Kind != "aws/ecs-task" || proposal.Target.Identity.Scheme != resourceScheme || proposal.Target.Identity.AuthorityID != parts[2] {
		return remediation.Plan{}, &remediation.IneligibleTargetError{ProviderID: PluginID, Reason: "target is not an ECS task owned by this AWS source"}
	}
	advisory := "Register a new revision of the task definition with trustedExecutionConfiguration.isolationMode set to ISOLATED_SANDBOX, redeploy the workload with that revision, and verify the replacement tasks report ISOLATED_SANDBOX."
	return remediation.NewAdvisoryPlan(proposal, PluginID, p.config.SourceID, actionID, advisory)
}

func (*Plugin) Prepare(context.Context, remediation.Proposal, remediation.Plan) (remediation.Preparation, error) {
	return remediation.Preparation{}, &remediation.AdvisoryOnlyError{ProviderID: PluginID, Operation: "prepare"}
}

func (*Plugin) Execute(context.Context, remediation.Proposal, remediation.Plan, remediation.Preparation) (remediation.ExecutionResult, error) {
	return remediation.ExecutionResult{}, &remediation.AdvisoryOnlyError{ProviderID: PluginID, Operation: "execute"}
}

func (*Plugin) Verify(context.Context, remediation.Proposal, remediation.Plan, remediation.ExecutionResult) (remediation.Verification, error) {
	return remediation.Verification{}, &remediation.AdvisoryOnlyError{ProviderID: PluginID, Operation: "verify"}
}
