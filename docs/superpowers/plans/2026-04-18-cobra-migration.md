# Cobra Migration (v2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Re-do the kingpin → cobra migration on top of current `main`, using the old `complete-cobra-migration` branch as a *pattern reference* only. End state: identical runtime behavior to current `main` for all 9 subcommands, plus a new `completion` subcommand.

**Architecture:** File-by-file rewrite on a new branch off `main`. Each commit leaves the repo compilable and tests passing. Global plumbing (`cli/global.go` + `main.go`) migrates first; then each command file (signature + `Configure*` body) migrates one at a time, re-registering itself in `main.go` as it goes. Test files migrate alongside their command. Kingpin dependency is removed last via `go mod tidy`.

**Tech Stack:** Go 1.21, cobra v1.x (latest), standard library.

**Reference files (read-only):** `complete-cobra-migration` branch's `main.go`, `cli/*.go` — use for pattern inspiration, *not* to copy-paste. Current `main` branch is the authoritative source of behavior.

---

## File Structure

| File | Action | Responsibility |
|---|---|---|
| `go.mod`, `go.sum` | modify | add `spf13/cobra`, remove `alecthomas/kingpin/v2` (last) |
| `cli/global.go` | rewrite `ConfigureGlobals` | cobra persistent flags, env var handling, completion for `--backend`/`--prompt` |
| `main.go` | rewrite | cobra root command, register subcommands, inline `completion` subcommand |
| `cli/clear.go` | rewrite `ConfigureClearCommand` | cobra subcommand wiring; `ClearCommand` body unchanged |
| `cli/list.go` | rewrite `ConfigureListCommand` | cobra subcommand wiring; body unchanged |
| `cli/list_test.go` | rewrite test harness | throwaway cobra root, `SetArgs`/`Execute` pattern |
| `cli/remove.go` | rewrite `ConfigureRemoveCommand` | cobra subcommand wiring; body unchanged |
| `cli/add.go` | rewrite `ConfigureAddCommand` | cobra subcommand wiring; body unchanged |
| `cli/add_test.go` | rewrite test harness | throwaway cobra root pattern |
| `cli/rotate.go` | rewrite `ConfigureRotateCommand` | cobra subcommand wiring; body unchanged |
| `cli/login.go` | rewrite `ConfigureLoginCommand` | cobra subcommand wiring; body unchanged |
| `cli/export.go` | rewrite `ConfigureExportCommand` | cobra subcommand wiring; body unchanged |
| `cli/export_test.go` | rewrite test harness | throwaway cobra root pattern |
| `cli/proxy.go` | rewrite `ConfigureProxyCommand` | cobra subcommand wiring; body unchanged |
| `cli/exec.go` | rewrite `ConfigureExecCommand` | cobra subcommand wiring with `SetInterspersed(false)`; body unchanged |
| `cli/exec_test.go` | rewrite test harness | throwaway cobra root pattern |

## Invariants (must hold at every commit)

1. `go build ./...` succeeds.
2. `go vet ./...` succeeds.
3. `go test ./...` passes for all currently-migrated commands (unmigrated commands continue to compile under their old kingpin signatures).
4. Business-logic functions (`ClearCommand`, `ExecCommand`, `AddCommand`, etc.) are byte-identical to their current `main` versions.

---

## Task 0: Branch setup

**Files:** none modified yet.

- [ ] **Step 1: Confirm on clean `main`**

Run:
```bash
cd /Users/chintan/projects/aws-vault
git status
git log --oneline -1
```
Expected: clean working tree (the `.tool-versions` untracked file is fine); HEAD at `de53cba docs: add cobra migration v2 design spec` or newer.

- [ ] **Step 2: Create and switch to migration branch**

Run:
```bash
git checkout -b cobra-migration-v2
```
Expected: `Switched to a new branch 'cobra-migration-v2'`.

---

## Task 1: Add cobra dependency

**Files:**
- Modify: `go.mod`, `go.sum`

- [ ] **Step 1: Add cobra**

Run:
```bash
go get github.com/spf13/cobra@latest
go mod tidy
```
Expected: `go.mod` now contains `github.com/spf13/cobra vX.Y.Z` under `require`. `kingpin/v2` still present.

- [ ] **Step 2: Verify build still works**

Run:
```bash
go build ./...
```
Expected: success, no output.

- [ ] **Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "chore: add spf13/cobra dependency"
```

---

## Task 2: Migrate `cli/global.go` to cobra signature + update `main.go` to cobra root (no subcommands yet)

**Files:**
- Modify: `cli/global.go`
- Modify: `main.go`

**Why together:** `ConfigureGlobals` signature change breaks `main.go` immediately. We migrate both atomically and register zero subcommands yet — the unused kingpin-signature `Configure*Command` functions in `cli/*.go` become dead code but still compile because kingpin is still imported by those files.

- [ ] **Step 1: Rewrite `cli/global.go`**

Replace the entire contents of `cli/global.go` with:

```go
package cli

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/byteness/aws-vault/v7/prompt"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	isatty "github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var keyringConfigDefaults = keyring.Config{
	ServiceName:              "aws-vault",
	FilePasswordFunc:         fileKeyringPassphrasePrompt,
	LibSecretCollectionName:  "awsvault",
	KWalletAppID:             "aws-vault",
	KWalletFolder:            "aws-vault",
	KeychainTrustApplication: true,
	WinCredPrefix:            "aws-vault",
	OPConnectTokenEnv:        "AWS_VAULT_OP_CONNECT_TOKEN",
	OPTokenEnv:               "AWS_VAULT_OP_SERVICE_ACCOUNT_TOKEN",
	OPDesktopAccountID:       "AWS_VAULT_OP_DESKTOP_ACCOUNT_ID",
	OPTokenFunc:              keyringPassphrasePrompt,
}

type AwsVault struct {
	Debug          bool
	KeyringConfig  keyring.Config
	KeyringBackend string
	promptDriver   string

	keyringImpl   keyring.Keyring
	awsConfigFile *vault.ConfigFile
	UseBiometrics bool
}

func isATerminal() bool {
	fd := os.Stdout.Fd()
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}

func (a *AwsVault) PromptDriver(avoidTerminalPrompt bool) string {
	if a.promptDriver == "" {
		a.promptDriver = "terminal"

		if !isATerminal() || avoidTerminalPrompt {
			for _, driver := range prompt.Available() {
				a.promptDriver = driver
				if driver != "terminal" {
					break
				}
			}
		}
	}

	log.Println("Using prompt driver: " + a.promptDriver)

	return a.promptDriver
}

func (a *AwsVault) Keyring() (keyring.Keyring, error) {
	if a.keyringImpl == nil {
		if a.KeyringBackend != "" {
			a.KeyringConfig.AllowedBackends = []keyring.BackendType{keyring.BackendType(a.KeyringBackend)}
		}
		var err error
		a.keyringImpl, err = keyring.Open(a.KeyringConfig)
		if err != nil {
			return nil, err
		}
	}

	return a.keyringImpl, nil
}

func (a *AwsVault) AwsConfigFile() (*vault.ConfigFile, error) {
	if a.awsConfigFile == nil {
		var err error
		a.awsConfigFile, err = vault.LoadConfigFromEnv()
		if err != nil {
			return nil, err
		}
	}

	return a.awsConfigFile, nil
}

func (a *AwsVault) MustGetProfileNames() []string {
	config, err := a.AwsConfigFile()
	if err != nil {
		log.Fatalf("Error loading AWS config: %s", err.Error())
	}
	return config.ProfileNames()
}

// CompleteProfileNames returns a cobra completion function producing profile names.
func (a *AwsVault) CompleteProfileNames() func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return a.MustGetProfileNames(), cobra.ShellCompDirectiveNoFileComp
	}
}

// readEnvDefault returns the env var value if set, otherwise fallback.
func readEnvDefault(name, fallback string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}
	return fallback
}

func ConfigureGlobals(rootCmd *cobra.Command) *AwsVault {
	a := &AwsVault{
		KeyringConfig: keyringConfigDefaults,
	}

	backendsAvailable := []string{}
	for _, backendType := range keyring.AvailableBackends() {
		backendsAvailable = append(backendsAvailable, string(backendType))
	}

	promptsAvailable := prompt.Available()

	rootCmd.PersistentFlags().BoolVar(&a.Debug, "debug", false, "Show debugging output")
	rootCmd.PersistentFlags().StringVar(&a.KeyringBackend, "backend",
		readEnvDefault("AWS_VAULT_BACKEND", backendsAvailable[0]),
		fmt.Sprintf("Secret backend to use %v", backendsAvailable))
	rootCmd.PersistentFlags().StringVar(&a.promptDriver, "prompt",
		os.Getenv("AWS_VAULT_PROMPT"),
		fmt.Sprintf("Prompt driver to use %v", promptsAvailable))
	rootCmd.PersistentFlags().StringVar(&a.KeyringConfig.KeychainName, "keychain",
		readEnvDefault("AWS_VAULT_KEYCHAIN_NAME", "aws-vault"),
		"Name of macOS keychain to use, if it doesn't exist it will be created")
	rootCmd.PersistentFlags().StringVar(&a.KeyringConfig.LibSecretCollectionName, "secret-service-collection",
		readEnvDefault("AWS_VAULT_SECRET_SERVICE_COLLECTION_NAME", "awsvault"),
		"Name of secret-service collection to use, if it doesn't exist it will be created")
	rootCmd.PersistentFlags().StringVar(&a.KeyringConfig.PassDir, "pass-dir",
		os.Getenv("AWS_VAULT_PASS_PASSWORD_STORE_DIR"),
		"Pass password store directory")
	rootCmd.PersistentFlags().StringVar(&a.KeyringConfig.PassCmd, "pass-cmd",
		os.Getenv("AWS_VAULT_PASS_CMD"),
		"Name of the pass executable")
	rootCmd.PersistentFlags().StringVar(&a.KeyringConfig.PassPrefix, "pass-prefix",
		os.Getenv("AWS_VAULT_PASS_PREFIX"),
		"Prefix to prepend to the item path stored in pass")
	rootCmd.PersistentFlags().StringVar(&a.KeyringConfig.FileDir, "file-dir",
		readEnvDefault("AWS_VAULT_FILE_DIR", "~/.awsvault/keys/"),
		"Directory for the \"file\" password store")

	rootCmd.PersistentFlags().DurationVar(&a.KeyringConfig.OPTimeout, "op-timeout", 15*time.Second,
		"Timeout for 1Password API operations (1Password Service Accounts only)")
	rootCmd.PersistentFlags().StringVar(&a.KeyringConfig.OPVaultID, "op-vault-id",
		os.Getenv("AWS_VAULT_OP_VAULT_ID"),
		"UUID of the 1Password vault")
	rootCmd.PersistentFlags().StringVar(&a.KeyringConfig.OPItemTitlePrefix, "op-item-title-prefix",
		readEnvDefault("AWS_VAULT_OP_ITEM_TITLE_PREFIX", "aws-vault"),
		"Prefix to prepend to 1Password item titles")
	rootCmd.PersistentFlags().StringVar(&a.KeyringConfig.OPItemTag, "op-item-tag",
		readEnvDefault("AWS_VAULT_OP_ITEM_TAG", "aws-vault"),
		"Tag to apply to 1Password items")
	rootCmd.PersistentFlags().StringVar(&a.KeyringConfig.OPConnectHost, "op-connect-host",
		os.Getenv("AWS_VAULT_OP_CONNECT_HOST"),
		"1Password Connect server HTTP(S) URI")
	rootCmd.PersistentFlags().StringVar(&a.KeyringConfig.OPDesktopAccountID, "op-desktop-account-id",
		os.Getenv("AWS_VAULT_OP_DESKTOP_ACCOUNT_ID"),
		"1Password Desktop App account name or account UUID")
	rootCmd.PersistentFlags().BoolVar(&a.UseBiometrics, "biometrics",
		os.Getenv("AWS_VAULT_BIOMETRICS") == "true",
		"Use biometric authentication if supported")

	_ = rootCmd.RegisterFlagCompletionFunc("backend", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return backendsAvailable, cobra.ShellCompDirectiveNoFileComp
	})
	_ = rootCmd.RegisterFlagCompletionFunc("prompt", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return promptsAvailable, cobra.ShellCompDirectiveNoFileComp
	})

	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if !a.Debug {
			log.SetOutput(io.Discard)
		}
		keyring.Debug = a.Debug

		if a.UseBiometrics {
			configureTouchID(&a.KeyringConfig)
		}

		log.Printf("aws-vault %s", rootCmd.Version)

		if a.promptDriver == "" {
			return nil
		}
		if a.promptDriver == "pass" {
			return fmt.Errorf("--prompt=pass (or AWS_VAULT_PROMPT=pass) has been removed from aws-vault as using TOTPs without " +
				"a dedicated device goes against security best practices. If you wish to continue using pass, " +
				"add `mfa_process = pass otp <your mfa_serial>` to profiles in your ~/.aws/config file.")
		}
		for _, v := range promptsAvailable {
			if v == a.promptDriver {
				return nil
			}
		}
		return fmt.Errorf("--prompt value must be one of %s, got '%s'", strings.Join(promptsAvailable, ","), a.promptDriver)
	}

	return a
}

func configureTouchID(k *keyring.Config) {
	k.UseBiometrics = true
	k.TouchIDAccount = "cc.byteness.aws-vault.biometrics"
	k.TouchIDService = "aws-vault"
}

func fileKeyringPassphrasePrompt(prompt string) (string, error) {
	if password, ok := os.LookupEnv("AWS_VAULT_FILE_PASSPHRASE"); ok {
		return password, nil
	}

	return keyringPassphrasePrompt(prompt)
}

func keyringPassphrasePrompt(prompt string) (string, error) {
	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	fmt.Println()
	return string(b), nil
}

// Archived library github.com/AlecAivazis/survey/v2
func pickAwsProfile(profiles []string) (string, error) {
	var ProfileName string

	prompt := &survey.Select{
		Message: "Choose AWS profile:",
		Options: profiles,
	}

	err := survey.AskOne(prompt, &ProfileName)

	return ProfileName, err
}

// Maintained library github.com/charmbracelet/huh (TODO: needs more testing)
func pickAwsProfile2(profiles []string) (string, error) {
	var ProfileName string

	var opts []huh.Option[string]
	for _, p := range profiles {
		opts = append(opts, huh.NewOption(p, p))
	}
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Choose AWS profile:").
				Options(opts...).
				Value(&ProfileName))).WithHeight(9)

	err := form.Run()
	blue := lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
	white := lipgloss.NewStyle().Foreground(lipgloss.Color("15"))
	fmt.Printf("%s %s\n", white.Render("Selected profile:"), blue.Render(fmt.Sprintf("%s", ProfileName)))

	return ProfileName, err
}
```

Note: `readEnvDefault` is a small helper. The `OPTimeout` default uses `15*time.Second` — add `"time"` to the import block at the top of the file.

- [ ] **Step 2: Rewrite `main.go`**

Replace the entire contents of `main.go` with:

```go
package main

import (
	"os"

	"github.com/byteness/aws-vault/v7/cli"
	"github.com/spf13/cobra"
)

// Version is provided at compile time
var Version = "dev"

func main() {
	rootCmd := &cobra.Command{
		Use:   "aws-vault",
		Short: "A vault for securely storing and accessing AWS credentials in development environments",
		Long:  "A vault for securely storing and accessing AWS credentials in development environments.",
	}
	rootCmd.Version = Version
	rootCmd.SetVersionTemplate("{{.Version}}\n")

	_ = cli.ConfigureGlobals(rootCmd)

	// Subcommands will be registered as they are migrated (Tasks 3-11).

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
```

- [ ] **Step 3: Build**

Run:
```bash
go build ./...
```
Expected: compiles. The old kingpin-signature `ConfigureAddCommand(*kingpin.Application, *AwsVault)` etc. are now dead code but still compile because `cli/*.go` imports kingpin directly.

- [ ] **Step 4: Test**

Run:
```bash
go test ./...
```
Expected: all existing cli tests still pass — they build their own throwaway `kingpin.Application`, attach the kingpin-signature `Configure*Command`, and exercise it. None of that depends on `main.go` or `cli/global.go`.

- [ ] **Step 5: Smoke test the binary**

Run:
```bash
go run . --help
```
Expected: cobra help output listing *only* the global flags (no subcommands yet, no completion yet). Exits 0.

- [ ] **Step 6: Commit**

```bash
git add cli/global.go main.go
git commit -m "refactor(cli): migrate ConfigureGlobals and main.go to cobra"
```

---

## Task 3: Migrate `cli/clear.go`

**Files:**
- Modify: `cli/clear.go`
- Modify: `main.go` (register the subcommand)

**Why first:** simplest command, no flags, single optional arg, no test file.

- [ ] **Step 1: Rewrite `cli/clear.go`**

Replace contents with:

```go
package cli

import (
	"fmt"

	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
	"github.com/spf13/cobra"
)

type ClearCommandInput struct {
	ProfileName string
}

func ConfigureClearCommand(a *AwsVault) *cobra.Command {
	input := ClearCommandInput{}

	cmd := &cobra.Command{
		Use:   "clear [profile]",
		Short: "Clear temporary credentials from the secure keystore",
		Long:  "Clear temporary credentials from the secure keystore.",
		Args:  cobra.MaximumNArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) == 0 {
				return a.CompleteProfileNames()(cmd, args, toComplete)
			}
			return nil, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				input.ProfileName = args[0]
			}

			keyring, err := a.Keyring()
			if err != nil {
				return err
			}
			awsConfigFile, err := a.AwsConfigFile()
			if err != nil {
				return err
			}

			return ClearCommand(input, awsConfigFile, keyring)
		},
	}

	return cmd
}

func ClearCommand(input ClearCommandInput, awsConfigFile *vault.ConfigFile, keyring keyring.Keyring) error {
	sessions := &vault.SessionKeyring{Keyring: keyring}
	oidcTokens := &vault.OIDCTokenKeyring{Keyring: keyring}
	var oldSessionsRemoved, numSessionsRemoved, numTokensRemoved int
	var err error
	if input.ProfileName == "" {
		oldSessionsRemoved, err = sessions.RemoveOldSessions()
		if err != nil {
			return err
		}
		numSessionsRemoved, err = sessions.RemoveAll()
		if err != nil {
			return err
		}
		numTokensRemoved, err = oidcTokens.RemoveAll()
		if err != nil {
			return err
		}
	} else {
		numSessionsRemoved, err = sessions.RemoveForProfile(input.ProfileName)
		if err != nil {
			return err
		}

		if profileSection, ok := awsConfigFile.ProfileSection(input.ProfileName); ok {
			if exists, _ := oidcTokens.Has(profileSection.SSOStartURL); exists {
				err = oidcTokens.Remove(profileSection.SSOStartURL)
				if err != nil {
					return err
				}
				numTokensRemoved = 1
			}
		}
	}
	fmt.Printf("Cleared %d sessions.\n", oldSessionsRemoved+numSessionsRemoved+numTokensRemoved)

	return nil
}
```

- [ ] **Step 2: Register in `main.go`**

In `main.go`, after the `_ = cli.ConfigureGlobals(rootCmd)` line, change to:
```go
	a := cli.ConfigureGlobals(rootCmd)
	rootCmd.AddCommand(cli.ConfigureClearCommand(a))
```

- [ ] **Step 3: Build + test**

```bash
go build ./...
go test ./...
go run . clear --help
```
Expected: build/test pass; `clear --help` shows cobra help.

- [ ] **Step 4: Commit**

```bash
git add cli/clear.go main.go
git commit -m "refactor(cli): migrate clear command to cobra"
```

---

## Task 4: Migrate `cli/list.go` + `cli/list_test.go`

**Files:**
- Modify: `cli/list.go`
- Modify: `cli/list_test.go`
- Modify: `main.go`

- [ ] **Step 1: Replace `ConfigureListCommand` in `cli/list.go`**

Keep `ListCommandInput` struct, `ListCommand` function body, `stringslice` helpers, and `sessionLabel` unchanged. Remove `"github.com/alecthomas/kingpin/v2"` and add `"github.com/spf13/cobra"` to imports. Replace the `ConfigureListCommand` function with:

```go
func ConfigureListCommand(a *AwsVault) *cobra.Command {
	input := ListCommandInput{}

	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List profiles, along with their credentials and sessions",
		Long:    "List profiles, along with their credentials and sessions.",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			keyring, err := a.Keyring()
			if err != nil {
				return err
			}
			awsConfigFile, err := a.AwsConfigFile()
			if err != nil {
				return err
			}
			return ListCommand(input, awsConfigFile, keyring)
		},
	}

	cmd.Flags().BoolVar(&input.OnlyProfiles, "profiles", false, "Show only the profile names")
	cmd.Flags().BoolVar(&input.OnlySessions, "sessions", false, "Show only the session names")
	cmd.Flags().BoolVar(&input.OnlyCredentials, "credentials", false, "Show only the profiles with stored credential")

	return cmd
}
```

- [ ] **Step 2: Rewrite `cli/list_test.go`**

Current file is an `Example` test that builds a kingpin app, attaches globals + the list command, and parses args. Replace contents entirely with:

```go
package cli

import (
	"github.com/byteness/keyring"
	"github.com/spf13/cobra"
)

func ExampleListCommand() {
	rootCmd := &cobra.Command{Use: "aws-vault"}
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true
	awsVault := ConfigureGlobals(rootCmd)
	awsVault.keyringImpl = keyring.NewArrayKeyring([]keyring.Item{
		{Key: "llamas", Data: []byte(`{"AccessKeyID":"ABC","SecretAccessKey":"XYZ"}`)},
	})
	rootCmd.AddCommand(ConfigureListCommand(awsVault))
	rootCmd.SetArgs([]string{"list", "--credentials"})
	_ = rootCmd.Execute()

	// Output:
	// llamas
}
```

`SilenceUsage` / `SilenceErrors` prevent cobra from printing usage text or `Error: ...` on error — the `// Output:` check is sensitive to any extra stdout. Apply to all Example tests.

- [ ] **Step 3: Register in `main.go`**

Add:
```go
	rootCmd.AddCommand(cli.ConfigureListCommand(a))
```

- [ ] **Step 4: Build + test**

```bash
go build ./...
go test ./cli/... -run TestList -v
go run . list --help
```
Expected: build + test pass; list help renders.

- [ ] **Step 5: Commit**

```bash
git add cli/list.go cli/list_test.go main.go
git commit -m "refactor(cli): migrate list command to cobra"
```

---

## Task 5: Migrate `cli/remove.go`

**Files:**
- Modify: `cli/remove.go`
- Modify: `main.go`

No test file for remove.

- [ ] **Step 1: Rewrite `cli/remove.go`**

Keep `RemoveCommandInput` struct and `RemoveCommand` function body unchanged. Remove `"github.com/alecthomas/kingpin/v2"` and add `"github.com/spf13/cobra"` to imports. Note the signature changes: `RemoveCommand` in current main takes only `(input, keyring)` — **not** `(input, awsConfigFile, keyring)` — verify that with `grep -n "^func RemoveCommand" cli/remove.go` before writing the `RunE`.

Replace `ConfigureRemoveCommand` with:

```go
func ConfigureRemoveCommand(a *AwsVault) *cobra.Command {
	input := RemoveCommandInput{}

	cmd := &cobra.Command{
		Use:     "remove <profile>",
		Aliases: []string{"rm"},
		Short:   "Remove credentials from the secure keystore",
		Long:    "Remove credentials from the secure keystore.",
		Args:    cobra.ExactArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) == 0 {
				return a.CompleteProfileNames()(cmd, args, toComplete)
			}
			return nil, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			input.ProfileName = args[0]
			keyring, err := a.Keyring()
			if err != nil {
				return err
			}
			return RemoveCommand(input, keyring)
		},
	}

	cmd.Flags().BoolVarP(&input.SessionsOnly, "sessions-only", "s", false, "Only remove sessions, leave credentials intact")
	_ = cmd.Flags().MarkHidden("sessions-only")
	cmd.Flags().BoolVarP(&input.Force, "force", "f", false, "Force-remove the profile without a prompt")

	return cmd
}
```

- [ ] **Step 2: Register in `main.go`**

```go
	rootCmd.AddCommand(cli.ConfigureRemoveCommand(a))
```

- [ ] **Step 3: Build + test + smoke**

```bash
go build ./...
go test ./...
go run . remove --help
```

- [ ] **Step 4: Commit**

```bash
git add cli/remove.go main.go
git commit -m "refactor(cli): migrate remove command to cobra"
```

---

## Task 6: Migrate `cli/add.go` + `cli/add_test.go`

**Files:**
- Modify: `cli/add.go`
- Modify: `cli/add_test.go`
- Modify: `main.go`

- [ ] **Step 1: Rewrite `cli/add.go`**

Keep `AddCommandInput` struct and `AddCommand` function body unchanged. Remove `"github.com/alecthomas/kingpin/v2"` and add `"github.com/spf13/cobra"` to imports. Note the current `AddCommand` signature is `AddCommand(input, keyring, awsConfigFile)` — argument order, verify with `grep -n "^func AddCommand" cli/add.go`.

Replace `ConfigureAddCommand` with:

```go
func ConfigureAddCommand(a *AwsVault) *cobra.Command {
	input := AddCommandInput{}

	cmd := &cobra.Command{
		Use:   "add <profile>",
		Short: "Add credentials to the secure keystore",
		Long:  "Add credentials to the secure keystore.",
		Args:  cobra.ExactArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return nil, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			input.ProfileName = args[0]
			keyring, err := a.Keyring()
			if err != nil {
				return err
			}
			awsConfigFile, err := a.AwsConfigFile()
			if err != nil {
				return err
			}
			return AddCommand(input, keyring, awsConfigFile)
		},
	}

	cmd.Flags().BoolVar(&input.FromEnv, "env", false, "Read the credentials from the environment (AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY)")
	cmd.Flags().BoolVar(&input.AddConfig, "add-config", true, "Add a profile to ~/.aws/config if one doesn't exist")

	return cmd
}
```

Note `--add-config` default is `true` to match the kingpin `Default("true")`.

- [ ] **Step 2: Rewrite `cli/add_test.go`**

Replace the full file with:

```go
package cli

import (
	"log"
	"os"

	"github.com/spf13/cobra"
)

func ExampleAddCommand() {
	f, err := os.CreateTemp("", "aws-config")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(f.Name())

	os.Setenv("AWS_CONFIG_FILE", f.Name())
	os.Setenv("AWS_ACCESS_KEY_ID", "llamas")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "rock")
	os.Setenv("AWS_VAULT_BACKEND", "file")
	os.Setenv("AWS_VAULT_FILE_PASSPHRASE", "password")

	defer os.Unsetenv("AWS_ACCESS_KEY_ID")
	defer os.Unsetenv("AWS_SECRET_ACCESS_KEY")
	defer os.Unsetenv("AWS_VAULT_BACKEND")
	defer os.Unsetenv("AWS_VAULT_FILE_PASSPHRASE")

	rootCmd := &cobra.Command{Use: "aws-vault"}
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true
	awsVault := ConfigureGlobals(rootCmd)
	rootCmd.AddCommand(ConfigureAddCommand(awsVault))
	rootCmd.SetArgs([]string{"--debug", "add", "--env", "foo"})
	_ = rootCmd.Execute()

	// Output:
	// Added credentials to profile "foo" in vault
}
```

Note the `--debug` must come *before* `add` (global flag), unlike in kingpin where it was positional-insensitive.

- [ ] **Step 3: Register in `main.go`**

```go
	rootCmd.AddCommand(cli.ConfigureAddCommand(a))
```

- [ ] **Step 4: Build + test**

```bash
go build ./...
go test ./cli/... -run TestAdd -v
go run . add --help
```

- [ ] **Step 5: Commit**

```bash
git add cli/add.go cli/add_test.go main.go
git commit -m "refactor(cli): migrate add command to cobra"
```

---

## Task 7: Migrate `cli/rotate.go`

**Files:**
- Modify: `cli/rotate.go`
- Modify: `main.go`

No test file for rotate. Note: the kingpin version falls back to `pickAwsProfile` if no profile was passed — that behavior must stay. `RotateCommand` signature is `RotateCommand(input, f, keyring)`.

- [ ] **Step 1: Rewrite `cli/rotate.go`**

Keep `RotateCommandInput` struct, `RotateCommand`, `retry`, `getUsernameIfAssumingRole`, and `getProfilesInChain` bodies unchanged. Remove `"github.com/alecthomas/kingpin/v2"` and add `"github.com/spf13/cobra"` to imports.

Replace `ConfigureRotateCommand` with:

```go
func ConfigureRotateCommand(a *AwsVault) *cobra.Command {
	input := RotateCommandInput{}

	cmd := &cobra.Command{
		Use:   "rotate [profile]",
		Short: "Rotate credentials",
		Long:  "Rotate credentials.",
		Args:  cobra.MaximumNArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) == 0 {
				return a.CompleteProfileNames()(cmd, args, toComplete)
			}
			return nil, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				input.ProfileName = args[0]
			}
			input.Config.MfaPromptMethod = a.PromptDriver(false)

			f, err := a.AwsConfigFile()
			if err != nil {
				return err
			}
			keyring, err := a.Keyring()
			if err != nil {
				return err
			}

			if input.ProfileName == "" {
				ProfileName, err := pickAwsProfile(f.ProfileNames())
				if err != nil {
					return fmt.Errorf("unable to select a 'profile'. Try --help: %w", err)
				}
				input.ProfileName = ProfileName
			}

			return RotateCommand(input, f, keyring)
		},
	}

	cmd.Flags().BoolVarP(&input.NoSession, "no-session", "n", false, "Use master credentials, no session or role used")

	return cmd
}
```

Note the kingpin version has ONLY `--no-session` flag (no `--region`, no `--mfa-token`). Don't add flags that aren't there.

- [ ] **Step 2: Register in `main.go`**

```go
	rootCmd.AddCommand(cli.ConfigureRotateCommand(a))
```

- [ ] **Step 3: Build + test + smoke**

```bash
go build ./...
go test ./...
go run . rotate --help
```

- [ ] **Step 4: Commit**

```bash
git add cli/rotate.go main.go
git commit -m "refactor(cli): migrate rotate command to cobra"
```

---

## Task 8: Migrate `cli/login.go`

**Files:**
- Modify: `cli/login.go`
- Modify: `main.go`

No test file for login. Current signature: `LoginCommand(ctx, input, f, keyring)`. Kingpin default for `--profile` is `os.Getenv("AWS_PROFILE")` — replicate that.

- [ ] **Step 1: Rewrite `cli/login.go`**

Keep `LoginCommandInput` struct, `getCredsProvider`, `LoginCommand`, `generateLoginURL`, `isCallerIdentityAssumedRole`, `createStaticCredentialsProvider`, `canProviderBeUsedForLogin`, and `requestSigninToken` unchanged. Remove `"github.com/alecthomas/kingpin/v2"` and add `"github.com/spf13/cobra"` to imports.

Replace `ConfigureLoginCommand` with:

```go
func ConfigureLoginCommand(a *AwsVault) *cobra.Command {
	input := LoginCommandInput{}

	cmd := &cobra.Command{
		Use:   "login [profile]",
		Short: "Generate a login link for the AWS Console",
		Long:  "Generate a login link for the AWS Console. If no profile is given, credentials are sourced from env vars.",
		Args:  cobra.MaximumNArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) == 0 {
				return a.CompleteProfileNames()(cmd, args, toComplete)
			}
			return nil, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				input.ProfileName = args[0]
			} else {
				input.ProfileName = os.Getenv("AWS_PROFILE")
			}
			input.Config.MfaPromptMethod = a.PromptDriver(false)
			input.Config.NonChainedGetSessionTokenDuration = input.SessionDuration
			input.Config.AssumeRoleDuration = input.SessionDuration
			input.Config.GetFederationTokenDuration = input.SessionDuration

			keyring, err := a.Keyring()
			if err != nil {
				return err
			}
			f, err := a.AwsConfigFile()
			if err != nil {
				return err
			}
			return LoginCommand(cmd.Context(), input, f, keyring)
		},
	}

	cmd.Flags().DurationVarP(&input.SessionDuration, "duration", "d", 0, "Duration of the assume-role or federated session. Defaults to 1h")
	cmd.Flags().BoolVarP(&input.NoSession, "no-session", "n", false, "Skip creating STS session with GetSessionToken")
	cmd.Flags().BoolVarP(&input.AutoLogout, "auto-logout", "a", os.Getenv("AWS_VAULT_AUTO_LOGOUT") == "true", "Auto logout when starting a new login")
	cmd.Flags().StringVarP(&input.Config.MfaToken, "mfa-token", "t", "", "The MFA token to use")
	cmd.Flags().StringVar(&input.Path, "path", "", "The AWS service you would like access")
	cmd.Flags().StringVar(&input.Config.Region, "region", "", "The AWS region")

	stdoutDefault := os.Getenv("AWS_VAULT_STDOUT") != ""
	cmd.Flags().BoolVarP(&input.UseStdout, "stdout", "s", stdoutDefault, "Print login URL to stdout instead of opening in default browser")

	return cmd
}
```

- [ ] **Step 2: Register in `main.go`**

```go
	rootCmd.AddCommand(cli.ConfigureLoginCommand(a))
```

- [ ] **Step 3: Build + test + smoke**

```bash
go build ./...
go test ./...
go run . login --help
```

- [ ] **Step 4: Commit**

```bash
git add cli/login.go main.go
git commit -m "refactor(cli): migrate login command to cobra"
```

---

## Task 9: Migrate `cli/export.go` + `cli/export_test.go`

**Files:**
- Modify: `cli/export.go`
- Modify: `cli/export_test.go`
- Modify: `main.go`

- [ ] **Step 1: Rewrite `cli/export.go`**

Keep `ExportCommandInput` struct, `FormatType*` vars, `ExportCommand` and any helper functions unchanged. Remove `"github.com/alecthomas/kingpin/v2"` and add `"github.com/spf13/cobra"` to imports.

Replace `ConfigureExportCommand` with:

```go
func ConfigureExportCommand(a *AwsVault) *cobra.Command {
	input := ExportCommandInput{}
	validFormats := []string{FormatTypeEnv, FormatTypeExportEnv, FormatTypeExportJSON, FormatTypeExportINI}

	cmd := &cobra.Command{
		Use:   "export [profile]",
		Short: "Export AWS credentials",
		Long:  "Export AWS credentials.",
		Args:  cobra.MaximumNArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) == 0 {
				return a.CompleteProfileNames()(cmd, args, toComplete)
			}
			return nil, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				input.ProfileName = args[0]
			}

			// Validate --format value (kingpin used EnumVar; cobra has no equivalent).
			valid := false
			for _, v := range validFormats {
				if v == input.Format {
					valid = true
					break
				}
			}
			if !valid {
				return fmt.Errorf("--format must be one of %v, got '%s'", validFormats, input.Format)
			}

			input.Config.MfaPromptMethod = a.PromptDriver(false)
			input.Config.NonChainedGetSessionTokenDuration = input.SessionDuration
			input.Config.AssumeRoleDuration = input.SessionDuration
			input.Config.SSOUseStdout = input.UseStdout

			f, err := a.AwsConfigFile()
			if err != nil {
				return err
			}
			keyring, err := a.Keyring()
			if err != nil {
				return err
			}
			if input.ProfileName == "" {
				ProfileName, err := pickAwsProfile(f.ProfileNames())
				if err != nil {
					return fmt.Errorf("unable to select a 'profile'. Try --help: %w", err)
				}
				input.ProfileName = ProfileName
			}
			return ExportCommand(input, f, keyring)
		},
	}

	cmd.Flags().DurationVarP(&input.SessionDuration, "duration", "d", 0, "Duration of the temporary or assume-role session. Defaults to 1h")
	cmd.Flags().BoolVarP(&input.NoSession, "no-session", "n", false, "Skip creating STS session with GetSessionToken")
	cmd.Flags().StringVar(&input.Config.Region, "region", "", "The AWS region")
	cmd.Flags().StringVarP(&input.Config.MfaToken, "mfa-token", "t", "", "The MFA token to use")
	cmd.Flags().StringVar(&input.Format, "format", FormatTypeEnv,
		fmt.Sprintf("Format to output credentials. Valid formats: %s, %s, %s, %s", FormatTypeEnv, FormatTypeExportEnv, FormatTypeExportJSON, FormatTypeExportINI))

	stdoutDefault := os.Getenv("AWS_VAULT_STDOUT") != ""
	cmd.Flags().BoolVar(&input.UseStdout, "stdout", stdoutDefault, "Print the SSO link to the terminal without automatically opening the browser")

	_ = cmd.RegisterFlagCompletionFunc("format", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return validFormats, cobra.ShellCompDirectiveNoFileComp
	})

	return cmd
}
```

- [ ] **Step 2: Rewrite `cli/export_test.go`**

Replace the full file with:

```go
package cli

import (
	"github.com/byteness/keyring"
	"github.com/spf13/cobra"
)

func ExampleExportCommand() {
	rootCmd := &cobra.Command{Use: "aws-vault"}
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true
	awsVault := ConfigureGlobals(rootCmd)
	awsVault.keyringImpl = keyring.NewArrayKeyring([]keyring.Item{
		{Key: "llamas", Data: []byte(`{"AccessKeyID":"ABC","SecretAccessKey":"XYZ"}`)},
	})
	rootCmd.AddCommand(ConfigureExportCommand(awsVault))
	rootCmd.SetArgs([]string{"export", "--format=ini", "--no-session", "llamas"})
	_ = rootCmd.Execute()

	// Output:
	// [llamas]
	// aws_access_key_id=ABC
	// aws_secret_access_key=XYZ
	// region=us-east-1
}
```

- [ ] **Step 3: Register in `main.go`**

```go
	rootCmd.AddCommand(cli.ConfigureExportCommand(a))
```

- [ ] **Step 4: Build + test + smoke**

```bash
go build ./...
go test ./cli/... -run TestExport -v
go run . export --help
```

- [ ] **Step 5: Commit**

```bash
git add cli/export.go cli/export_test.go main.go
git commit -m "refactor(cli): migrate export command to cobra"
```

---

## Task 10: Migrate `cli/proxy.go`

**Files:**
- Modify: `cli/proxy.go`
- Modify: `main.go`

`proxy` does not take an `*AwsVault` — it's the EC2 metadata proxy subprocess. Has `--stop` flag, `server` alias, and is hidden.

- [ ] **Step 1: Rewrite `cli/proxy.go`**

Keep `handleSigTerm` unchanged. Replace contents with:

```go
package cli

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/byteness/aws-vault/v7/server"
	"github.com/spf13/cobra"
)

func ConfigureProxyCommand() *cobra.Command {
	stop := false

	cmd := &cobra.Command{
		Use:     "proxy",
		Aliases: []string{"server"},
		Short:   "Start a proxy for the ec2 instance role server locally",
		Long:    "Start a proxy for the ec2 instance role server locally.",
		Hidden:  true,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if stop {
				server.StopProxy()
				return nil
			}
			handleSigTerm()
			return server.StartProxy()
		},
	}

	cmd.Flags().BoolVar(&stop, "stop", false, "Stop the proxy")

	return cmd
}

func handleSigTerm() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		server.Shutdown()
		os.Exit(1)
	}()
}
```

- [ ] **Step 2: Register in `main.go`**

```go
	rootCmd.AddCommand(cli.ConfigureProxyCommand())
```

- [ ] **Step 3: Build + test + smoke**

```bash
go build ./...
go test ./...
go run . proxy --help
```

- [ ] **Step 4: Commit**

```bash
git add cli/proxy.go main.go
git commit -m "refactor(cli): migrate proxy command to cobra"
```

---

## Task 11: Migrate `cli/exec.go` + `cli/exec_test.go`

**Files:**
- Modify: `cli/exec.go`
- Modify: `cli/exec_test.go`
- Modify: `main.go`

**The hairy one.** Positional args: `[profile] [cmd] [args...]`. Needs `SetInterspersed(false)` so flags after the profile pass through to the wrapped command. Has `--profile-env` flag (added post-revert in PR #340).

- [ ] **Step 1: Rewrite `cli/exec.go` — replace the `ConfigureExecCommand` function**

Replace the existing `ConfigureExecCommand` (lines 70-177 in current `cli/exec.go`). Keep `ExecCommandInput` struct, `validate()`, `hasBackgroundServer()`, `ExecCommand()`, `createEnv()`, `startEcsServerAndSetEnv()`, `addCredsToEnv()`, `environ`, `getDefaultShell()`, `runSubProcess()`, `doExecSyscall()`, and the `printHelpMessage`/`printToStderr` helpers — byte-identical.

```go
func ConfigureExecCommand(a *AwsVault) *cobra.Command {
	input := ExecCommandInput{}

	cmd := &cobra.Command{
		Use:   "exec [profile] [cmd] [args...]",
		Short: "Execute a command with AWS credentials",
		Long:  "Execute a command with AWS credentials.",
		Args:  cobra.ArbitraryArgs,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) == 0 {
				return a.CompleteProfileNames()(cmd, args, toComplete)
			}
			return nil, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				input.ProfileName = args[0]
			}
			if len(args) > 1 {
				input.Command = args[1]
				input.Args = args[2:]
			}
			if input.ProfileName == "" {
				input.ProfileName = os.Getenv("AWS_PROFILE")
			}

			input.Config.MfaPromptMethod = a.PromptDriver(hasBackgroundServer(input))
			input.Config.NonChainedGetSessionTokenDuration = input.SessionDuration
			input.Config.AssumeRoleDuration = input.SessionDuration
			input.Config.SSOUseStdout = input.UseStdout
			input.ShowHelpMessages = !a.Debug && input.Command == "" && isATerminal() && os.Getenv("AWS_VAULT_DISABLE_HELP_MESSAGE") != "1"

			f, err := a.AwsConfigFile()
			if err != nil {
				return err
			}
			keyring, err := a.Keyring()
			if err != nil {
				return err
			}

			if input.ProfileName == "" {
				ProfileName, err := pickAwsProfile(f.ProfileNames())
				if err != nil {
					return fmt.Errorf("unable to select a 'profile'. Try --help: %w", err)
				}
				input.ProfileName = ProfileName
			}

			exitcode := 0
			if input.JSONDeprecated {
				exportCommandInput := ExportCommandInput{
					ProfileName:     input.ProfileName,
					Format:          "json",
					Config:          input.Config,
					SessionDuration: input.SessionDuration,
					NoSession:       input.NoSession,
				}
				err = ExportCommand(exportCommandInput, f, keyring)
			} else {
				exitcode, err = ExecCommand(input, f, keyring)
			}
			if err != nil {
				return err
			}

			os.Exit(exitcode)
			return nil
		},
	}

	// Critical: prevent cobra from parsing flags AFTER the positional profile arg —
	// those flags belong to the wrapped command.
	cmd.Flags().SetInterspersed(false)

	cmd.Flags().DurationVarP(&input.SessionDuration, "duration", "d", 0, "Duration of the temporary or assume-role session. Defaults to 1h")
	cmd.Flags().BoolVarP(&input.NoSession, "no-session", "n", false, "Skip creating STS session with GetSessionToken")
	cmd.Flags().StringVar(&input.Config.Region, "region", "", "The AWS region")
	cmd.Flags().StringVarP(&input.Config.MfaToken, "mfa-token", "t", "", "The MFA token to use")
	cmd.Flags().BoolVarP(&input.JSONDeprecated, "json", "j", false, "Output credentials in JSON that can be used by credential_process")
	_ = cmd.Flags().MarkHidden("json")
	cmd.Flags().BoolVarP(&input.StartEcsServer, "server", "s", false, "Alias for --ecs-server")
	cmd.Flags().BoolVar(&input.StartEc2Server, "ec2-server", false, "Run a EC2 metadata server in the background for credentials")
	cmd.Flags().BoolVar(&input.StartEcsServer, "ecs-server", false, "Run a ECS credential server in the background for credentials (the SDK or app must support AWS_CONTAINER_CREDENTIALS_FULL_URI)")
	cmd.Flags().BoolVar(&input.Lazy, "lazy", false, "When using --ecs-server, lazily fetch credentials")

	stdoutDefault := os.Getenv("AWS_VAULT_STDOUT") != ""
	cmd.Flags().BoolVar(&input.UseStdout, "stdout", stdoutDefault, "Print the SSO link to the terminal without automatically opening the browser")

	profileEnvDefault := os.Getenv("AWS_VAULT_PROFILE_ENV") != ""
	cmd.Flags().BoolVar(&input.UseProfileEnv, "profile-env", profileEnvDefault, "Set AWS_PROFILE instead of injecting AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")

	return cmd
}
```

Also:
1. Remove `"github.com/alecthomas/kingpin/v2"` from imports.
2. Add `"github.com/spf13/cobra"` to imports.

- [ ] **Step 2: Rewrite `cli/exec_test.go`**

Current file is `ExampleExecCommand` using the same kingpin pattern as list/export tests. Replace contents with:

```go
package cli

import (
	"github.com/byteness/keyring"
	"github.com/spf13/cobra"
)

func ExampleExecCommand() {
	rootCmd := &cobra.Command{Use: "aws-vault"}
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true
	awsVault := ConfigureGlobals(rootCmd)
	awsVault.keyringImpl = keyring.NewArrayKeyring([]keyring.Item{
		{Key: "llamas", Data: []byte(`{"AccessKeyID":"ABC","SecretAccessKey":"XYZ"}`)},
	})
	rootCmd.AddCommand(ConfigureExecCommand(awsVault))
	rootCmd.SetArgs([]string{"--debug", "exec", "--no-session", "llamas", "--", "sh", "-c", "echo $AWS_ACCESS_KEY_ID"})
	_ = rootCmd.Execute()

	// Output:
	// ABC
}
```

Note: the exec command calls `os.Exit(exitcode)` at the end of `RunE` — same as the kingpin action did. The Example test works because the subprocess writes "ABC\n" to stdout *before* the os.Exit fires; stdout capture is compared against `// Output: ABC` by the Go test runner. This is fragile but existing behavior — preserve it.

- [ ] **Step 3: Register in `main.go`**

```go
	rootCmd.AddCommand(cli.ConfigureExecCommand(a))
```

- [ ] **Step 4: Build + test + smoke**

```bash
go build ./...
go test ./cli/... -run TestExec -v
go run . exec --help
```

Expected: `exec --help` renders; tests pass.

- [ ] **Step 5: Commit**

```bash
git add cli/exec.go cli/exec_test.go main.go
git commit -m "refactor(cli): migrate exec command to cobra (last)"
```

---

## Task 12: Add the `completion` subcommand

**Files:**
- Modify: `main.go`

- [ ] **Step 1: Add inline completion command to `main.go`**

Insert before `rootCmd.Execute()`:

```go
	rootCmd.AddCommand(&cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion scripts",
		Long: `Generate shell completion scripts for aws-vault.

  Bash:
    source <(aws-vault completion bash)
  Zsh:
    aws-vault completion zsh > "${fpath[1]}/_aws-vault"
  Fish:
    aws-vault completion fish | source
  Powershell:
    aws-vault completion powershell | Out-String | Invoke-Expression
`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return cmd.Root().GenBashCompletion(os.Stdout)
			case "zsh":
				return cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				return cmd.Root().GenFishCompletion(os.Stdout, true)
			case "powershell":
				return cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
			}
			return nil
		},
	})
```

- [ ] **Step 2: Build + smoke**

```bash
go build ./...
go run . completion zsh | head -10
go run . completion bash | head -10
```

Expected: shell completion scripts print.

- [ ] **Step 3: Commit**

```bash
git add main.go
git commit -m "feat(cli): add completion subcommand (bash/zsh/fish/powershell)"
```

---

## Task 13: Drop kingpin from module

**Files:**
- Modify: `go.mod`, `go.sum`

- [ ] **Step 1: Grep to confirm kingpin has no remaining usages**

```bash
grep -rn "alecthomas/kingpin" cli/ main.go
```
Expected: no output (kingpin is unused in Go source).

- [ ] **Step 2: Tidy modules**

```bash
go mod tidy
```
Expected: `go.mod` no longer lists `alecthomas/kingpin/v2`; `go.sum` prunes its entries.

- [ ] **Step 3: Full build + test**

```bash
go build ./...
go vet ./...
go test ./...
```
Expected: everything clean.

- [ ] **Step 4: Commit**

```bash
git add go.mod go.sum
git commit -m "chore: remove kingpin dependency"
```

---

## Task 14: Validation gate

**Files:** none.

Manual smoke tests against real environment — operator must have at least one AWS profile configured.

- [ ] **Step 1: Build binary**

```bash
make aws-vault
```
(Or `go build -o aws-vault .` if you don't want codesigning.)

- [ ] **Step 2: Root help**

```bash
./aws-vault --help
./aws-vault --version
```
Expected: help lists all subcommands (`add`, `clear`, `completion`, `exec`, `export`, `help`, `list`, `login`, `remove`, `rotate`). `proxy` is hidden and won't appear. Version prints `dev` or the `git describe` output.

- [ ] **Step 3: Non-destructive read commands**

```bash
./aws-vault list
./aws-vault list --help
./aws-vault clear --help
```
Expected: no crashes, expected output shape.

- [ ] **Step 4: Exec passthrough**

```bash
./aws-vault exec <your-profile> -- env | grep -E '^AWS_'
```
Expected: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_VAULT`, `AWS_REGION` (if profile has one) visible.

- [ ] **Step 5: Exec with --profile-env**

```bash
./aws-vault exec --profile-env <your-profile> -- env | grep -E '^AWS_'
```
Expected: `AWS_PROFILE` set, `AWS_VAULT` set, `AWS_ACCESS_KEY_ID` **absent**.

- [ ] **Step 6: Login (only if you actually use it)**

```bash
./aws-vault login --stdout <your-profile>
```
Expected: SSO login URL printed to stdout. Do not open the browser unless intentional.

- [ ] **Step 7: Completion smoke**

```bash
./aws-vault completion zsh | head -20
./aws-vault completion bash | head -20
```

- [ ] **Step 8: If all pass, merge**

```bash
git checkout main
git merge --ff-only cobra-migration-v2
```
(Use `--ff-only` to preserve the clean commit history. If non-fast-forward, you can choose `git merge --squash` instead.)

---

## Rollback

If any task fails and recovery is non-trivial:

```bash
git checkout main
git branch -D cobra-migration-v2    # only if you want to throw out the work
```

Or preserve branch for later investigation and just `git checkout main` without deleting.

## Post-implementation

- Branch deleted or kept per your preference.
- No tag, no release, no upstream PR (per design).
- `install` target: `make install` copies the binary to `~/bin/aws-vault`.
