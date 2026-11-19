package aws

import (
	"os"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/discovery"
	"github.com/spf13/pflag"
)

// CLIConfig contains AWS-owned runtime options.
type CLIConfig struct {
	Region            string
	ECS               bool
	PollInterval      time.Duration
	EventsQueueURL    string
	FirehoseStreamARN string
	FirehoseAccessKey string
}

// RegisterFlags registers AWS flags in the aws-* namespace.
func (config *CLIConfig) RegisterFlags(flags *pflag.FlagSet) error {
	return discovery.RegisterPluginFlags(flags, PluginID, func(pluginFlags *discovery.PluginFlags) {
		pluginFlags.StringVar(&config.Region, "region", "", "enable AWS EC2 discovery in this region")
		pluginFlags.BoolVar(&config.ECS, "ecs", false, "enable ECS task discovery")
		pluginFlags.DurationVar(&config.PollInterval, "poll-interval", defaultPollInterval, "AWS inventory polling interval")
		pluginFlags.StringVar(&config.EventsQueueURL, "events-queue-url", "", "SQS queue receiving EventBridge CloudTrail events")
		pluginFlags.StringVar(&config.FirehoseStreamARN, "firehose-stream-arn", "", "enable VPC Flow Log ingestion from this Firehose stream")
		pluginFlags.StringVar(&config.FirehoseAccessKey, "firehose-access-key", os.Getenv("AGENTSHIELD_AWS_FIREHOSE_ACCESS_KEY"), "Firehose shared key; defaults to AGENTSHIELD_AWS_FIREHOSE_ACCESS_KEY")
	})
}
