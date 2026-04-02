// Package policy implements the multi-layer policy engine that evaluates
// whether agent actions (send, read, delete, etc.) are allowed, denied, or held
// for review. It combines hard guardrails from config (Layer A) and dynamic
// database rules (Layer C).
package policy

import (
	"context"
	"fmt"
	"strings"

	"github.com/luxemque/msngr/internal/config"
	"github.com/luxemque/msngr/internal/db"
)

// Action describes an operation an agent wants to perform.
type Action struct {
	Type           string // send, read, delete, mark, download_attachment, list, search
	AgentName      string // display name (unique, used for rule matching)
	AgentNumericID int64  // numeric ID (used for DB permission checks)
	AccountID      int64
	FromAddr       string
	ToAddrs        []string
	CcAddrs        []string
	Subject        string
	BodyText       string
	Attachments    []AttachmentInfo
	MessageSize    int64
}

// AttachmentInfo describes a single attachment.
type AttachmentInfo struct {
	Filename string
	MimeType string
	Size     int64
}

// Decision is the result of evaluating an action through the policy layers.
type Decision struct {
	Outcome      string        // allow, deny, hold
	MatchedRules []MatchedRule // all rules that matched during evaluation
	FinalRule    *MatchedRule  // the rule that determined the outcome
	Explanation  string
}

// MatchedRule records a single rule match during evaluation.
type MatchedRule struct {
	RuleID      int64
	Name        string
	Layer       string // A, C
	Action      string // allow, deny, hold
	Explanation string
}

// Engine evaluates actions through the 2-layer policy stack.
type Engine struct {
	db           *db.DB
	hardGuardrails *HardGuardrails
}

// NewEngine creates a policy engine backed by the given database.
func NewEngine(database *db.DB, hardCfg config.HardPolicyConfig) *Engine {
	return &Engine{
		db:             database,
		hardGuardrails: NewHardGuardrails(hardCfg),
	}
}

// Evaluate runs the action through layers A -> C.
// Any deny stops immediately. Hold is recorded but evaluation continues
// (a later deny overrides a hold). If no rule matches, the default is deny.
func (e *Engine) Evaluate(ctx context.Context, action Action) (*Decision, error) {
	decision := &Decision{
		Outcome: "deny", // safe default
	}

	// --- Layer A: hard guardrails from config ---
	layerAResults, err := e.hardGuardrails.Evaluate(ctx, action, e.db)
	if err != nil {
		return nil, fmt.Errorf("layer A evaluation: %w", err)
	}
	decision.MatchedRules = append(decision.MatchedRules, layerAResults...)
	if d := firstDeny(layerAResults); d != nil {
		decision.Outcome = "deny"
		decision.FinalRule = d
		decision.Explanation = d.Explanation
		return decision, nil
	}

	// --- Layer C: dynamic DB rules ---
	layerCResults, err := evaluateLayerC(ctx, action, e.db)
	if err != nil {
		return nil, fmt.Errorf("layer C evaluation: %w", err)
	}
	decision.MatchedRules = append(decision.MatchedRules, layerCResults...)
	if d := firstDeny(layerCResults); d != nil {
		decision.Outcome = "deny"
		decision.FinalRule = d
		decision.Explanation = d.Explanation
		return decision, nil
	}

	// Check for holds across all layers.
	if h := firstHold(decision.MatchedRules); h != nil {
		decision.Outcome = "hold"
		decision.FinalRule = h
		decision.Explanation = h.Explanation
		return decision, nil
	}

	// Check for any allow across all layers.
	if a := firstAllow(decision.MatchedRules); a != nil {
		decision.Outcome = "allow"
		decision.FinalRule = a
		decision.Explanation = a.Explanation
		return decision, nil
	}

	// No rule matched at all: default deny.
	decision.Explanation = "no policy rule matched; default deny"
	return decision, nil
}

// firstDeny returns the first deny rule in the list, or nil.
func firstDeny(rules []MatchedRule) *MatchedRule {
	for i := range rules {
		if rules[i].Action == "deny" {
			return &rules[i]
		}
	}
	return nil
}

// firstHold returns the first hold rule in the list, or nil.
func firstHold(rules []MatchedRule) *MatchedRule {
	for i := range rules {
		if rules[i].Action == "hold" {
			return &rules[i]
		}
	}
	return nil
}

// firstAllow returns the first allow rule in the list, or nil.
func firstAllow(rules []MatchedRule) *MatchedRule {
	for i := range rules {
		if rules[i].Action == "allow" {
			return &rules[i]
		}
	}
	return nil
}

// FinalRuleName returns the name of the final rule, or "" if no rule matched.
func (d *Decision) FinalRuleName() string {
	if d.FinalRule != nil {
		return d.FinalRule.Name
	}
	return ""
}

// domainFromAddr extracts the lowercased domain part from an email address.
func domainFromAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	// Handle "Name <email@domain>" format.
	if idx := strings.LastIndex(addr, "<"); idx >= 0 {
		addr = strings.TrimRight(addr[idx+1:], ">")
	}
	if at := strings.LastIndex(addr, "@"); at >= 0 {
		return strings.ToLower(addr[at+1:])
	}
	return strings.ToLower(addr)
}
