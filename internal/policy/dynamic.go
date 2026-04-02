package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/luxemque/msngr/internal/db"
)

// matchCriteria represents the parsed JSON from a rule's match_criteria column.
// The "agent_id" JSON key is kept for backward compatibility with stored rules;
// it is matched against the agent's display name (Action.AgentName).
type matchCriteria struct {
	AgentID           *string  `json:"agent_id"`
	AccountID         *int64   `json:"account_id"`
	Sender            *string  `json:"sender"`
	Recipient         *string  `json:"recipient"`
	Domain            *string  `json:"domain"`
	ActionType        *string  `json:"action_type"`
	KeywordsPresent   []string `json:"keywords_present"`
	KeywordsAbsent    []string `json:"keywords_absent"`
	AttachmentPresent *bool    `json:"attachment_present"`
	AttachmentTypes   []string `json:"attachment_types"`
	MaxSize           *int64   `json:"max_size"`
	MaxRecipients     *int     `json:"max_recipients"`
}

// evaluateLayerC loads enabled rules from the database and matches them
// against the action. Rules are evaluated in priority order (lowest number
// first). The first matching rule's action determines the outcome; subsequent
// matching rules are still recorded for the audit trail but do not override
// the first match's decision.
func evaluateLayerC(ctx context.Context, action Action, database *db.DB) ([]MatchedRule, error) {
	rules, err := database.GetEnabledRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("load enabled rules: %w", err)
	}

	var matched []MatchedRule
	decided := false

	for _, rule := range rules {
		// Only evaluate Layer C rules here.
		if rule.Layer != "C" {
			continue
		}

		var criteria matchCriteria
		if err := json.Unmarshal([]byte(rule.MatchCriteria), &criteria); err != nil {
			// Skip rules with unparsable criteria; log would go here.
			continue
		}

		if !ruleMatches(criteria, action) {
			continue
		}

		matched = append(matched, MatchedRule{
			RuleID:      rule.ID,
			Name:        rule.Name,
			Layer:       "C",
			Action:      rule.Action,
			Explanation: rule.Explanation,
		})

		// The first matching rule (by priority) determines the outcome.
		// A deny stops immediately; otherwise record the decision and
		// continue collecting matches for the audit trail but mark that
		// the decision has been made.
		if !decided {
			decided = true
			// If the first match is a deny, stop evaluation entirely.
			if rule.Action == "deny" {
				break
			}
		}
	}

	// If the first match was not deny/hold, suppress later hold/deny matches
	// from overriding the first match by only returning the deciding rule's
	// action for the first entry (subsequent entries are audit-only).
	// The engine uses firstDeny/firstHold/firstAllow, so we need to ensure
	// only the first match's action is used for the decision. We do this by
	// returning only the first match when it is an allow, to prevent a later
	// hold from overriding it within the same layer.
	if len(matched) > 0 && matched[0].Action == "allow" {
		// Keep only the first (deciding) allow rule from Layer C so that
		// later hold/deny matches within the same layer don't override it.
		return matched[:1], nil
	}

	return matched, nil
}

// ruleMatches returns true if all non-nil criteria fields match the action.
// An empty criteria object matches everything.
func ruleMatches(c matchCriteria, a Action) bool {
	if c.AgentID != nil && *c.AgentID != a.AgentName {
		return false
	}

	if c.AccountID != nil && *c.AccountID != a.AccountID {
		return false
	}

	if c.ActionType != nil && *c.ActionType != a.Type {
		return false
	}

	if c.Sender != nil {
		if !matchStringOrRegex(*c.Sender, a.FromAddr) {
			return false
		}
	}

	if c.Recipient != nil {
		allRecipients := append(append([]string{}, a.ToAddrs...), a.CcAddrs...)
		if !anyMatchStringOrRegex(*c.Recipient, allRecipients) {
			return false
		}
	}

	if c.Domain != nil {
		allRecipients := append(append([]string{}, a.ToAddrs...), a.CcAddrs...)
		if !anyDomainMatches(*c.Domain, allRecipients) {
			return false
		}
	}

	if c.KeywordsPresent != nil {
		text := strings.ToLower(a.Subject + " " + a.BodyText)
		for _, kw := range c.KeywordsPresent {
			if !strings.Contains(text, strings.ToLower(kw)) {
				return false
			}
		}
	}

	if c.KeywordsAbsent != nil {
		text := strings.ToLower(a.Subject + " " + a.BodyText)
		for _, kw := range c.KeywordsAbsent {
			if strings.Contains(text, strings.ToLower(kw)) {
				return false
			}
		}
	}

	if c.AttachmentPresent != nil {
		hasAttachments := len(a.Attachments) > 0
		if *c.AttachmentPresent != hasAttachments {
			return false
		}
	}

	if c.AttachmentTypes != nil {
		if !attachmentTypesMatch(c.AttachmentTypes, a.Attachments) {
			return false
		}
	}

	if c.MaxSize != nil && a.MessageSize > *c.MaxSize {
		return false
	}

	if c.MaxRecipients != nil {
		total := len(a.ToAddrs) + len(a.CcAddrs)
		if total > *c.MaxRecipients {
			return false
		}
	}

	return true
}

// matchStringOrRegex checks if value matches the pattern.
// If the pattern starts and ends with /, it is treated as a regex.
// Otherwise it is a case-insensitive exact match.
func matchStringOrRegex(pattern, value string) bool {
	if len(pattern) >= 2 && pattern[0] == '/' && pattern[len(pattern)-1] == '/' {
		expr := pattern[1 : len(pattern)-1]
		re, err := regexp.Compile("(?i)" + expr)
		if err != nil {
			return false
		}
		return re.MatchString(value)
	}
	return strings.EqualFold(pattern, value)
}

// anyMatchStringOrRegex returns true if at least one value matches the pattern.
func anyMatchStringOrRegex(pattern string, values []string) bool {
	for _, v := range values {
		if matchStringOrRegex(pattern, v) {
			return true
		}
	}
	return false
}

// anyDomainMatches returns true if at least one recipient's domain matches.
func anyDomainMatches(pattern string, addresses []string) bool {
	for _, addr := range addresses {
		domain := domainFromAddr(addr)
		if matchStringOrRegex(pattern, domain) {
			return true
		}
	}
	return false
}

// attachmentTypesMatch returns true if at least one attachment matches one of
// the required MIME types or file extensions.
func attachmentTypesMatch(types []string, attachments []AttachmentInfo) bool {
	if len(attachments) == 0 {
		return false
	}
	for _, att := range attachments {
		for _, t := range types {
			t = strings.ToLower(t)
			// Check MIME type match.
			if strings.EqualFold(att.MimeType, t) {
				return true
			}
			// Check by extension (e.g., ".pdf").
			ext := strings.ToLower(filepath.Ext(att.Filename))
			if ext == t {
				return true
			}
		}
	}
	return false
}
