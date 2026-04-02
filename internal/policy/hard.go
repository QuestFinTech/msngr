package policy

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/luxemque/msngr/internal/config"
	"github.com/luxemque/msngr/internal/db"
)

// HardGuardrails holds the configuration for Layer A hard-coded checks.
type HardGuardrails struct {
	// MaxMessageSizeBytes is the maximum allowed message size in bytes.
	MaxMessageSizeBytes int64
	// MaxRecipients is the maximum number of combined To and Cc recipients.
	MaxRecipients int
	// DenyDomains is the list of recipient domains that are always rejected.
	DenyDomains []string
	// ForbiddenExtensions is the set of file extensions (e.g. ".exe") that are blocked.
	ForbiddenExtensions map[string]bool
}

// NewHardGuardrails creates guardrails from the YAML hard-policy config.
func NewHardGuardrails(cfg config.HardPolicyConfig) *HardGuardrails {
	exts := make(map[string]bool)
	for _, e := range cfg.ForbiddenExtensions {
		exts[strings.ToLower(e)] = true
	}
	return &HardGuardrails{
		MaxMessageSizeBytes: int64(cfg.MaxMessageSizeMB) * 1024 * 1024,
		MaxRecipients:       cfg.MaxRecipients,
		DenyDomains:         cfg.DenyDomains,
		ForbiddenExtensions: exts,
	}
}

// Evaluate runs all Layer A checks against the action.
// It returns matched rules (allow or deny). A deny means the action must stop.
func (hg *HardGuardrails) Evaluate(ctx context.Context, action Action, database *db.DB) ([]MatchedRule, error) {
	var matched []MatchedRule

	// 1. Mandatory agent identity for all actions.
	if action.AgentName == "" {
		matched = append(matched, MatchedRule{
			RuleID:      0,
			Name:        "agent-identity-required",
			Layer:       "A",
			Action:      "deny",
			Explanation: "all actions require a non-empty agent identity",
		})
		return matched, nil
	}

	// 2. For send actions, verify agent has the "send" capability on this account.
	if action.Type == "send" {
		ok, err := database.CheckAgentCapability(ctx, action.AgentNumericID, action.AccountID, "send")
		if err != nil {
			return nil, fmt.Errorf("check agent-account mapping: %w", err)
		}
		if !ok {
			matched = append(matched, MatchedRule{
				RuleID:      0,
				Name:        "agent-account-mapping",
				Layer:       "A",
				Action:      "deny",
				Explanation: fmt.Sprintf("agent %q is not permitted to send via account %d", action.AgentName, action.AccountID),
			})
			return matched, nil
		}
	}

	// 3. Max message size.
	if action.MessageSize > hg.MaxMessageSizeBytes {
		matched = append(matched, MatchedRule{
			RuleID:      0,
			Name:        "max-message-size",
			Layer:       "A",
			Action:      "deny",
			Explanation: fmt.Sprintf("message size %d bytes exceeds maximum of %d bytes", action.MessageSize, hg.MaxMessageSizeBytes),
		})
		return matched, nil
	}

	// 4. Max recipients (To + Cc combined).
	totalRecipients := len(action.ToAddrs) + len(action.CcAddrs)
	if totalRecipients > hg.MaxRecipients {
		matched = append(matched, MatchedRule{
			RuleID:      0,
			Name:        "max-recipients",
			Layer:       "A",
			Action:      "deny",
			Explanation: fmt.Sprintf("total recipients %d exceeds maximum of %d", totalRecipients, hg.MaxRecipients),
		})
		return matched, nil
	}

	// 5. Forbidden attachment extensions.
	for _, att := range action.Attachments {
		ext := strings.ToLower(filepath.Ext(att.Filename))
		if hg.ForbiddenExtensions[ext] {
			matched = append(matched, MatchedRule{
				RuleID:      0,
				Name:        "forbidden-attachment-ext",
				Layer:       "A",
				Action:      "deny",
				Explanation: fmt.Sprintf("attachment %q has forbidden extension %q", att.Filename, ext),
			})
			return matched, nil
		}
	}

	// 6. Absolute deny domains.
	if len(hg.DenyDomains) > 0 {
		denySet := make(map[string]bool, len(hg.DenyDomains))
		for _, d := range hg.DenyDomains {
			denySet[strings.ToLower(d)] = true
		}

		allRecipients := make([]string, 0, len(action.ToAddrs)+len(action.CcAddrs))
		allRecipients = append(allRecipients, action.ToAddrs...)
		allRecipients = append(allRecipients, action.CcAddrs...)

		for _, addr := range allRecipients {
			domain := domainFromAddr(addr)
			if denySet[domain] {
				matched = append(matched, MatchedRule{
					RuleID:      0,
					Name:        "deny-domain",
					Layer:       "A",
					Action:      "deny",
					Explanation: fmt.Sprintf("recipient domain %q is in the absolute deny list", domain),
				})
				return matched, nil
			}
		}
	}

	// All Layer A checks passed: record an allow so the audit trail is complete.
	matched = append(matched, MatchedRule{
		RuleID:      0,
		Name:        "hard-guardrails-pass",
		Layer:       "A",
		Action:      "allow",
		Explanation: "all Layer A hard-coded guardrails passed",
	})
	return matched, nil
}
