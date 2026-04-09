// Package main is the CLI entrypoint for the MSNGR gateway service.
package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/luxemque/msngr/internal/config"
	"github.com/luxemque/msngr/internal/db"
	imappoller "github.com/luxemque/msngr/internal/imap"
	"github.com/luxemque/msngr/internal/mcp"
	"github.com/luxemque/msngr/internal/policy"
	"github.com/luxemque/msngr/internal/queue"
	"github.com/luxemque/msngr/internal/storage"
	"github.com/luxemque/msngr/internal/web"
)

var (
	// Version is the semantic version of this build, set at link time.
	Version = "dev"
	// Commit is the git commit hash of this build, set at link time.
	Commit = "unknown"
	// BuildTime is the timestamp when this binary was built, set at link time.
	BuildTime = "unknown"
)

const banner = `
  __  __ ____  _   _  ____ ____
 |  \/  / ___|| \ | |/ ___|  _ \
 | |\/| \___ \|  \| | |  _| |_) |
 | |  | |___) | |\  | |_| |  _ <
 |_|  |_|____/|_| \_|\____|_| \_\
`

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "run":
		cmdRun()
	case "init":
		cmdInit()
	case "doctor":
		cmdDoctor()
	case "config":
		if len(os.Args) >= 3 && os.Args[2] == "check" {
			cmdConfigCheck()
		} else {
			fmt.Fprintf(os.Stderr, "Unknown config subcommand. Usage: msngr config check\n")
			os.Exit(1)
		}
	case "rule":
		if len(os.Args) >= 3 && os.Args[2] == "simulate" {
			cmdRuleSimulate()
		} else {
			fmt.Fprintf(os.Stderr, "Unknown rule subcommand. Usage: msngr rule simulate [flags]\n")
			os.Exit(1)
		}
	case "export":
		if len(os.Args) >= 3 && os.Args[2] == "audit" {
			cmdExportAudit()
		} else {
			fmt.Fprintf(os.Stderr, "Unknown export subcommand. Usage: msngr export audit [--since DATE] [--until DATE] [--format json|csv]\n")
			os.Exit(1)
		}
	case "version":
		fmt.Printf("msngr %s (commit: %s, built: %s)\n", Version, Commit, BuildTime)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(`Usage: msngr <command> [options]

Commands:
  run            Start the MSNGR gateway service
  init           Initialize the database schema
  doctor         Check system health and configuration
  config check   Validate configuration file
  rule simulate  Simulate a policy evaluation without executing
  export audit   Export audit events to stdout
  version        Print version information
  help           Show this help message

Options:
  --config <path>   Path to config file (default: config.yaml)

Export audit options:
  --since <date>    Start date (ISO 8601, e.g. 2025-01-01)
  --until <date>    End date (ISO 8601, e.g. 2025-12-31)
  --format <fmt>    Output format: json (default) or csv
`)
}

func configPath() string {
	for i, arg := range os.Args {
		if arg == "--config" && i+1 < len(os.Args) {
			return os.Args[i+1]
		}
		if strings.HasPrefix(arg, "--config=") {
			return strings.TrimPrefix(arg, "--config=")
		}
	}
	return "config.yaml"
}

func setupLogging(level string) {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})))
}

func loadConfig() *config.Config {
	cfg, err := config.Load(configPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}
	return cfg
}

func openDB(cfg *config.Config) *db.DB {
	database, err := db.Open(cfg.DB.Path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening database: %v\n", err)
		os.Exit(1)
	}
	return database
}

func cmdRun() {
	fmt.Print(banner)
	fmt.Printf("  v%s\n\n", Version)

	cfg := loadConfig()
	setupLogging(cfg.Log.Level)

	database := openDB(cfg)
	defer database.Close()

	if err := database.InitSchema(); err != nil {
		slog.Error("Schema initialization failed", "error", err)
		os.Exit(1)
	}

	store := storage.NewStore(cfg.StoragePath)

	// Create policy engine and MCP server.
	policyEngine := policy.NewEngine(database, cfg.HardPolicy)
	mcpSrv := mcp.NewServer(database, policyEngine, store, Version, cfg.Session.MCPTimeoutMinutes)

	srv := web.NewServer(database, store, cfg.Listen, Version, cfg.HardPolicy, cfg.Session.OperatorTimeoutMinutes)
	srv.SetMCPHandler(mcpSrv.Handler())

	// Graceful shutdown on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Start background services.
	poller := imappoller.NewPoller(database, store, cfg.Ticks.IMAPPollMs)
	poller.Start(ctx)

	queueProc := queue.NewProcessor(database, cfg.Ticks.QueueProcessMs)
	go queueProc.Start(ctx)

	go func() {
		slog.Info("Starting MSNGR gateway", "listen", cfg.Listen)
		if err := srv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("Server error", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("Shutting down")
	poller.Stop()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("Shutdown error", "error", err)
	}
}

func cmdInit() {
	cfg := loadConfig()
	setupLogging(cfg.Log.Level)

	database := openDB(cfg)
	defer database.Close()

	if err := database.InitSchema(); err != nil {
		slog.Error("Schema initialization failed", "error", err)
		os.Exit(1)
	}
	slog.Info("Database initialized", "path", cfg.DB.Path)
}

func cmdDoctor() {
	fmt.Println("MSNGR Doctor")
	fmt.Println("============")
	hasError := false

	// 1. Check config.
	fmt.Print("Config: ")
	cfg, err := config.Load(configPath())
	if err != nil {
		fmt.Printf("FAIL - %v\n", err)
		hasError = true
	} else {
		fmt.Println("OK")
		if issues := validateConfig(cfg); len(issues) > 0 {
			for _, issue := range issues {
				fmt.Printf("  WARNING: %s\n", issue)
			}
		}
	}

	if cfg == nil {
		fmt.Println("\nCannot continue without valid config.")
		os.Exit(1)
	}

	// 2. Check database.
	fmt.Print("Database: ")
	database, err := db.Open(cfg.DB.Path)
	if err != nil {
		fmt.Printf("FAIL - %v\n", err)
		os.Exit(1)
	}
	defer database.Close()

	if err := database.Ping(); err != nil {
		fmt.Printf("FAIL - %v\n", err)
		hasError = true
	} else {
		fmt.Printf("OK (%s)\n", cfg.DB.Path)
	}

	// 3. Check accounts health.
	fmt.Print("Accounts: ")
	stats, err := database.GetDashboardStats()
	if err != nil {
		fmt.Printf("FAIL - %v\n", err)
		hasError = true
	} else {
		unhealthy, _ := database.GetUnhealthyAccountCount()
		if unhealthy > 0 {
			fmt.Printf("%d total, %d unhealthy\n", stats.Accounts, unhealthy)
		} else {
			fmt.Printf("%d total, all healthy\n", stats.Accounts)
		}
		fmt.Printf("  Agents: %d, Queue depth: %d, Pending holds: %d, Rules: %d\n",
			stats.Agents, stats.QueueDepth, stats.PendingHolds, stats.Rules)
	}

	fmt.Println()
	if hasError {
		fmt.Println("Result: ISSUES FOUND")
		os.Exit(1)
	}
	fmt.Println("Result: ALL OK")
}

func cmdConfigCheck() {
	fmt.Print("Loading config: ")
	cfg, err := config.Load(configPath())
	if err != nil {
		fmt.Printf("FAIL\n  %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK")

	issues := validateConfig(cfg)
	if len(issues) > 0 {
		fmt.Println("Issues found:")
		for _, issue := range issues {
			fmt.Printf("  - %s\n", issue)
		}
		os.Exit(1)
	}
	fmt.Println("Config is valid.")
}

func validateConfig(cfg *config.Config) []string {
	var issues []string
	if cfg.EncryptionKey == "" {
		issues = append(issues, "encryption_key is not set; credentials will not be encrypted")
	}
	if cfg.Listen == "" {
		issues = append(issues, "listen address is empty")
	}
	if cfg.DB.Path == "" {
		issues = append(issues, "db.path is empty")
	}
	return issues
}

func cmdExportAudit() {
	var since, until, format string
	// Parse flags from os.Args[3:] (after "export audit").
	args := os.Args[3:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--since":
			if i+1 < len(args) {
				i++
				since = args[i]
			}
		case "--until":
			if i+1 < len(args) {
				i++
				until = args[i]
			}
		case "--format":
			if i+1 < len(args) {
				i++
				format = args[i]
			}
		}
	}
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "csv" {
		fmt.Fprintf(os.Stderr, "Invalid format %q; must be json or csv\n", format)
		os.Exit(1)
	}

	cfg := loadConfig()
	database := openDB(cfg)
	defer database.Close()

	if err := database.InitSchema(); err != nil {
		fmt.Fprintf(os.Stderr, "Schema initialization failed: %v\n", err)
		os.Exit(1)
	}

	events, err := database.ExportAuditEvents(since, until)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error exporting audit events: %v\n", err)
		os.Exit(1)
	}

	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(events); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
			os.Exit(1)
		}
	case "csv":
		w := csv.NewWriter(os.Stdout)
		// Header row.
		w.Write([]string{"id", "actor_type", "actor_id", "action", "target_type", "target_id", "outcome", "details_json", "correlation_id", "created_at"})
		for _, e := range events {
			w.Write([]string{
				strconv.FormatInt(e.ID, 10),
				e.ActorType,
				e.ActorID,
				e.Action,
				e.TargetType,
				e.TargetID,
				e.Outcome,
				e.DetailsJSON,
				e.CorrelationID,
				e.CreatedAt,
			})
		}
		w.Flush()
		if err := w.Error(); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing CSV: %v\n", err)
			os.Exit(1)
		}
	}
}

func cmdRuleSimulate() {
	fs := flag.NewFlagSet("simulate", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to config file")
	agent := fs.String("agent", "", "agent string ID (required)")
	account := fs.Int64("account", 0, "account ID")
	action := fs.String("action", "", "action type: send, read, delete, mark, download_attachment (required)")
	to := fs.String("to", "", "recipient addresses (comma-separated)")
	cc := fs.String("cc", "", "CC addresses (comma-separated)")
	subject := fs.String("subject", "", "message subject")
	body := fs.String("body", "", "message body text")
	size := fs.Int64("size", 0, "message size in bytes")
	attachment := fs.String("attachment", "", "attachment filename")

	// Parse flags after "rule simulate" (os.Args[3:]).
	if err := fs.Parse(os.Args[3:]); err != nil {
		os.Exit(1)
	}

	if *agent == "" || *action == "" {
		fmt.Fprintf(os.Stderr, "Error: --agent and --action are required\n")
		fs.Usage()
		os.Exit(1)
	}

	// Override config path if provided via --config flag.
	if *cfgPath != "" {
		os.Args = append(os.Args, "--config", *cfgPath)
	}

	cfg := loadConfig()
	database := openDB(cfg)
	defer database.Close()

	if err := database.InitSchema(); err != nil {
		fmt.Fprintf(os.Stderr, "Schema initialization failed: %v\n", err)
		os.Exit(1)
	}

	// Build the policy action from flags.
	act := policy.Action{
		Type:        *action,
		AgentName:   *agent,
		AccountID:   *account,
		Subject:     *subject,
		BodyText:    *body,
		MessageSize: *size,
	}
	if *to != "" {
		act.ToAddrs = splitAndTrim(*to)
	}
	if *cc != "" {
		act.CcAddrs = splitAndTrim(*cc)
	}
	if *attachment != "" {
		act.Attachments = []policy.AttachmentInfo{{Filename: *attachment}}
	}

	engine := policy.NewEngine(database, cfg.HardPolicy)
	decision, err := engine.Evaluate(context.Background(), act)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error evaluating policy: %v\n", err)
		os.Exit(1)
	}

	// Print formatted result.
	fmt.Printf("Decision: %s\n", strings.ToUpper(decision.Outcome))
	if decision.Explanation != "" {
		fmt.Printf("Explanation: %s\n", decision.Explanation)
	}

	if len(decision.MatchedRules) > 0 {
		fmt.Println()
		fmt.Println("Matched Rules:")
		for _, r := range decision.MatchedRules {
			fmt.Printf("  [Layer %s] %s — %s\n", r.Layer, r.Name, r.Action)
		}
	}

	if decision.FinalRule != nil {
		fmt.Println()
		fmt.Printf("Final Rule: %s\n", decision.FinalRule.Name)
	}
}

func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
