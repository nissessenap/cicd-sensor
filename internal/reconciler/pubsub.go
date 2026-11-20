package reconciler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"cloud.google.com/go/pubsub/v2"
)

// ConsumeRecords receives sensor records from subscription until ctx is
// done. A record is acked once handled or found unusable, and nacked when
// the store failed so Pub/Sub redelivers it.
func ConsumeRecords(ctx context.Context, client *pubsub.Client, subscription string, handler *RecordHandler, logger *slog.Logger) error {
	err := client.Subscriber(subscription).Receive(ctx, func(ctx context.Context, msg *pubsub.Message) {
		if err := handler.HandleRecord(ctx, msg.Attributes, msg.Data); err != nil {
			logger.ErrorContext(ctx, "record_store_failed", "error", err)
			msg.Nack()
			return
		}
		msg.Ack()
	})
	if err != nil {
		return fmt.Errorf("receive from subscription %s: %w", subscription, err)
	}
	return nil
}

// PubSubFindingPublisher publishes each finding as one JSON message, shaped
// like the manager's Pub/Sub sink output so one consumer can read both.
type PubSubFindingPublisher struct {
	publisher *pubsub.Publisher
}

// NewPubSubFindingPublisher publishes to topic in the client's project.
func NewPubSubFindingPublisher(client *pubsub.Client, topic string) *PubSubFindingPublisher {
	return &PubSubFindingPublisher{publisher: client.Publisher(topic)}
}

// Publish blocks until Pub/Sub has accepted the finding.
func (p *PubSubFindingPublisher) Publish(ctx context.Context, finding Finding) error {
	data, err := json.Marshal(finding)
	if err != nil {
		return fmt.Errorf("marshal finding: %w", err)
	}
	result := p.publisher.Publish(ctx, &pubsub.Message{
		Data:       data,
		Attributes: findingAttributes(finding),
	})
	if _, err := result.Get(ctx); err != nil {
		return fmt.Errorf("publish finding: %w", err)
	}
	return nil
}

// Stop flushes pending messages and releases the publisher.
func (p *PubSubFindingPublisher) Stop() {
	p.publisher.Stop()
}

func findingAttributes(finding Finding) map[string]string {
	return map[string]string{
		"content_type":  "application/json",
		"log_type":      "missing_telemetry",
		"verdict":       string(finding.Verdict),
		"provider":      "github",
		"provider_host": finding.ProviderHost,
		"project_path":  finding.Repository,
	}
}
