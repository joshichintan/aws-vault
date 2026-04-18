# Cobra Migration (v2) — Design

**Date:** 2026-04-18
**Fork:** `github.com/byteness/aws-vault` (personal fork, local use only)
**Branch target:** `cobra-migration-v2` off current `main`

## Context

The upstream fork previously merged a kingpin → cobra migration (PR #172, commits `4d9f549` + `ba28b61`) and then reverted it (PR #238, commit `5f43ef2`, 2025-12-05). The revert reason was strategic, not technical: *"Reverts ByteNess/aws-vault#172 to keep `main` on v7 and branched v8."* No v8 branch exists in this fork.

Since the revert, `main` has accumulated 182 commits that continue to edit the kingpin-based CLI files — notably:

- YubiKey MFA prompt improvements (PR #349, #351)
- `--profile-env` flag on `exec` (PR #340)
- Testing and linting helper exports (PR #350)
- Dependency bumps

The pre-revert `complete-cobra-migration` branch still exists but is frozen before all of this work.

## Goal

Re-do the cobra migration on top of current `main`, using the `complete-cobra-migration` branch as a *pattern reference* (not a source). End state: `aws-vault` binary behaves identically to current `main` for all 9 commands, plus gains a `completion` subcommand for shell tab-completion.

## Non-goals

- No release, no tag, no GitHub Actions publish.
- No upstream PR.
- No module path change — stays on `github.com/byteness/aws-vault/v7`.
- No business-logic changes. Every `XCommand(input, …)` function (e.g. `ClearCommand`, `ExecCommand`) stays byte-identical.

## Scope

**Files touched (~14):**

- `main.go`
- `go.mod`, `go.sum`
- `cli/global.go`
- `cli/add.go`, `cli/clear.go`, `cli/exec.go`, `cli/export.go`, `cli/list.go`, `cli/login.go`, `cli/proxy.go`, `cli/remove.go`, `cli/rotate.go`
- `cli/add_test.go`, `cli/exec_test.go`, `cli/export_test.go`, `cli/list_test.go`

## Migration Pattern

Mechanical, per-file transformation:

| Kingpin | Cobra |
|---|---|
| `func ConfigureXCommand(app *kingpin.Application, a *AwsVault)` | `func ConfigureXCommand(a *AwsVault) *cobra.Command` |
| `app.Command("name", "help")` | `&cobra.Command{Use: "name", Short: "help", Long: "help"}` |
| `cmd.Arg("x", "…").StringVar(&v)` | `Args: cobra.ExactArgs/MaximumNArgs(N)` + extract `args[0]` in `RunE` |
| `cmd.Flag("f", "…").StringVar(&v)` | `cmd.Flags().StringVar(&v, "f", default, "…")` |
| `cmd.Flag(...).HintAction(fn)` | `cmd.RegisterFlagCompletionFunc("f", …)` |
| `cmd.Arg(...).HintAction(fn)` | `ValidArgsFunction: func(...) { a.CompleteProfileNames()(…) }` |
| `cmd.Action(func(c *kingpin.ParseContext) error)` | `RunE: func(cmd *cobra.Command, args []string) error` |
| `app.FatalIfError(err, "x")` | `return fmt.Errorf("x: %w", err)` |

**`main.go`:** `kingpin.New()` → `&cobra.Command{Use: "aws-vault", …}`; `app.Parse(os.Args[1:])` → `rootCmd.Execute()`; add inline `completion` subcommand (bash/zsh/fish/powershell) borrowed from the old cobra branch.

**`cli/global.go`:** `ConfigureGlobals(app *kingpin.Application) *AwsVault` → `ConfigureGlobals(cmd *cobra.Command) *AwsVault`. Global flags attach to `cmd.PersistentFlags()` instead of `app.Flag(...)`.

**Tests (`*_test.go`):** build a throwaway `rootCmd := &cobra.Command{Use: "aws-vault"}`, attach the configured subcommand, call `rootCmd.SetArgs(...)` + `rootCmd.Execute()` (pattern from the old cobra branch).

**Write fresh, not copy:** for each file, read (a) the current kingpin version on `main` to preserve behavior and (b) the old cobra version for the pattern — but *write* the result fresh so nothing from the 182 post-revert commits is dropped.

## Known Risks

1. **`exec` is the hairy one.** 185 lines with `--` separator handling for subprocess wrapping, signal forwarding, plus the new `--profile-env` flag from PR #340. Cobra's arg parsing is stricter than kingpin by default — will need `cmd.Flags().SetInterspersed(false)` so flags after the profile pass through to the wrapped command.

2. **`HintAction` vs `ValidArgsFunction`.** Kingpin's hint fires on Tab only; cobra's validator can also *reject* args if misconfigured. Must use `cobra.ShellCompDirectiveNoFileComp` to match kingpin's "suggestions only" behavior.

3. **Error output format differs.** Kingpin prints `aws-vault: error: X`; cobra prints `Error: X` + usage. Acceptable for personal use. Flag if it breaks any local scripts/aliases.

4. **`--backend` global flag enum.** Kingpin had `.Enum("wincred","keychain",…)`. No direct cobra equivalent. Old branch documents valid values instead of validating. Keep that approach.

## Validation Gate

Before merging `cobra-migration-v2` to `main`:

```
go build ./...                                  # compiles clean
go vet ./...                                    # no vet errors
go test ./...                                   # all tests pass
./aws-vault --help                              # help text renders
./aws-vault list                                # smoke-test against real keystore
./aws-vault exec <profile> -- env | grep AWS_   # exec passthrough works
./aws-vault completion zsh | head -5            # new completion works
```

Per-command manual smoke tests (most-used flag combinations) to be enumerated in the implementation plan.

## Execution Order

1. **Deps:** `go get github.com/spf13/cobra@latest`; `go mod tidy`. Keep kingpin installed — intermediate states need to compile.
2. **`cli/global.go`:** migrate `ConfigureGlobals` first; everything depends on it.
3. **Leaf command files** in increasing order of complexity, each compiled + tested before moving on:
   `clear.go` → `list.go` → `remove.go` → `add.go` → `rotate.go` → `login.go` → `export.go` → `proxy.go` → `exec.go`.
4. **`main.go`:** swap kingpin root for cobra root; register subcommands; add inline `completion` subcommand.
5. **Test files:** `add_test.go`, `exec_test.go`, `export_test.go`, `list_test.go` ported using the throwaway-root pattern.
6. **Drop kingpin:** `go mod tidy` removes it from `go.mod` / `go.sum`.
7. **Validation gate:** run commands above.
8. **Merge to `main`:** fast-forward or squash (user's call). No tag, no release.

## Invariants

- **Project compiles at every commit.** During step 2, `cli/global.go` must hold either a kingpin shim or `main.go` migrates first with stub calls. Decided during implementation.
- **Commit strategy:** one commit per file/step — ~12-15 small commits — so `git bisect` is useful if something regresses.
- **Business-logic functions unchanged.** `ClearCommand`, `ExecCommand`, `AddCommand`, etc. must be byte-identical to their current `main` versions.
