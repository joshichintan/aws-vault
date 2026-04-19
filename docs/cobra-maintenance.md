# Cobra Maintenance Guide

Operational notes for this fork's cobra-based CLI. Read this before:

- Merging upstream (ByteNess) changes that touch `cli/*.go` or `main.go`.
- Adding a new subcommand.
- Adding a new global flag.
- Changing any existing flag.

Upstream remains on **kingpin**; this fork runs on **cobra**. Every kingpin change we pick up needs a tiny translation step. This doc captures the mapping so the translation is mechanical.

---

## 1. Architecture invariants

Keep these true at every commit:

1. Each subcommand lives in `cli/<name>.go` with a function `ConfigureXCommand(a *AwsVault) *cobra.Command` (exception: `proxy` takes no `AwsVault`).
2. The business-logic function (e.g. `ClearCommand`, `ExecCommand`) is untouched by the cobra layer — only the `Configure*Command` wrapper changes.
3. `main.go` registers each subcommand via `rootCmd.AddCommand(cli.ConfigureXCommand(a))`.
4. No `kingpin` import anywhere in `cli/` or `main.go`. If upstream adds one back, this guide tells you how to translate it.
5. Root command has a `RunE: func(cmd *cobra.Command, args []string) error { return cmd.Help() }` so bare `aws-vault` prints help — cobra otherwise prints just the long description when no subcommands are registered.

---

## 2. Kingpin → Cobra translation table

Every time upstream adds a new flag/arg/action, consult this table. The left column is what you'll see in upstream's kingpin code; the right column is what to write in our cobra equivalent.

| Kingpin | Cobra |
|---|---|
| `func ConfigureXCommand(app *kingpin.Application, a *AwsVault)` | `func ConfigureXCommand(a *AwsVault) *cobra.Command` — returns `*cobra.Command` |
| `app.Command("name", "help").Alias("other")` | `&cobra.Command{Use: "name", Aliases: []string{"other"}, Short: "help", Long: "help."}` |
| `cmd.Arg("x", "…").Required().StringVar(&v)` | `Args: cobra.ExactArgs(1)` + extract `v = args[0]` in `RunE` |
| `cmd.Arg("x", "…").StringVar(&v)` (optional) | `Args: cobra.MaximumNArgs(1)` + `if len(args) > 0 { v = args[0] }` in `RunE` |
| `cmd.Arg("profile", "…").HintAction(a.MustGetProfileNames).StringVar(&v)` | `ValidArgsFunction: func(...) { if len(args)==0 { return a.CompleteProfileNames()(...) }; return nil, cobra.ShellCompDirectiveNoFileComp }` |
| `cmd.Flag("f", "…").StringVar(&v)` | `cmd.Flags().StringVar(&v, "f", "", "…")` |
| `cmd.Flag("f", "…").Short('f').StringVar(&v)` | `cmd.Flags().StringVarP(&v, "f", "f", "", "…")` (note: `StringVarP`) |
| `cmd.Flag("f", "…").Default("x").StringVar(&v)` | `cmd.Flags().StringVar(&v, "f", "x", "…")` |
| `cmd.Flag("f", "…").Envar("ENV_X").StringVar(&v)` | `cmd.Flags().StringVar(&v, "f", os.Getenv("ENV_X"), "…")` — cobra has no native env binding |
| `cmd.Flag("f", "…").Envar("ENV_X").Default("x").StringVar(&v)` | Use the `readEnvDefault("ENV_X", "x")` helper in `cli/global.go` |
| `cmd.Flag("f", "…").OverrideDefaultFromEnvar("AWS_VAULT_FOO").BoolVar(&v)` | `cmd.Flags().BoolVar(&v, "f", os.Getenv("AWS_VAULT_FOO") != "", "…")` |
| `cmd.Flag("f", "…").DurationVar(&v)` | `cmd.Flags().DurationVar(&v, "f", 0, "…")` |
| `cmd.Flag("f", "…").Hidden().BoolVar(&v)` | `cmd.Flags().BoolVar(&v, "f", false, "…")` then `_ = cmd.Flags().MarkHidden("f")` |
| `cmd.Flag("f", "…").EnumVar(&v, "a", "b", "c")` | `cmd.Flags().StringVar(&v, "f", "a", "…")` + validate manually in `PersistentPreRunE` / `RunE` (cobra has no enum flag) |
| `cmd.Action(func(c *kingpin.ParseContext) error)` | `RunE: func(cmd *cobra.Command, args []string) error` |
| `app.FatalIfError(err, "x")` | `return fmt.Errorf("x: %w", err)` (cobra handles exit codes via `RunE` return value) |
| `app.PreAction(func)` | `rootCmd.PersistentPreRunE = func(cmd, args) error { … }` — applies to all subcommands |
| `app.Validate(func)` | Same as PreAction — do it in `PersistentPreRunE` |

---

## 3. How to merge an upstream change that modifies an existing command

When upstream (ByteNess) changes `cli/<cmd>.go` on their kingpin-based branch and we want it on our cobra branch:

1. **Cherry-pick or merge** the upstream commit onto our branch. It'll land a `cli/<cmd>.go` file with kingpin imports + kingpin API calls. Expect compilation failure.
2. **Do NOT revert**. Instead, translate.
3. For each conflict, apply the translation table above. Specifically:
   - Look for new `cmd.Flag(…)` / `cmd.Arg(…)` / `cmd.Action(…)` chains — rewrite each one.
   - Preserve the struct definitions and `XCommand` function body byte-for-byte.
   - Re-add the kingpin import only if you're going to fully convert — don't leave partial kingpin in.
4. **Run**:
   ```
   go build ./...
   go vet ./...
   go test ./...
   go run . <cmd> --help    # spot-check help text
   ```
5. **Commit** with a message that names both: `refactor(cli): merge upstream X and translate to cobra`.

**If a new env var is added** — don't forget env-var bindings (kingpin's `.Envar()` has no cobra equivalent). Use `os.Getenv` manually.

**If a new enum flag is added** — add manual validation in `PersistentPreRunE` (for globals) or `RunE` (for subcommand flags). Don't silently drop the validation.

---

## 4. How to add a brand-new subcommand

1. Create `cli/<name>.go` mirroring the shape of `cli/clear.go` (simplest template):

   ```go
   package cli

   import (
       "github.com/spf13/cobra"
   )

   type NewCommandInput struct { /* fields */ }

   func ConfigureNewCommand(a *AwsVault) *cobra.Command {
       input := NewCommandInput{}
       cmd := &cobra.Command{
           Use:   "new [profile]",
           Short: "...",
           Long:  "...",
           Args:  cobra.MaximumNArgs(1),
           ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
               if len(args) == 0 {
                   return a.CompleteProfileNames()(cmd, args, toComplete)
               }
               return nil, cobra.ShellCompDirectiveNoFileComp
           },
           RunE: func(cmd *cobra.Command, args []string) error {
               if len(args) > 0 { input.ProfileName = args[0] }
               // ... wire up Keyring / AwsConfigFile as needed
               return NewCommand(input /*, ... */)
           },
       }
       // cmd.Flags().BoolVar(...)
       return cmd
   }

   func NewCommand(input NewCommandInput /*, ... */) error { /* business logic */ }
   ```

2. Register in `main.go`:
   ```go
   rootCmd.AddCommand(cli.ConfigureNewCommand(a))
   ```

3. If it exec-wraps another process (like `exec`), add:
   ```go
   cmd.Flags().SetInterspersed(false)
   ```
   and handle the `--` separator in `RunE`:
   ```go
   if len(cmdArgs) > 0 && cmdArgs[0] == "--" {
       cmdArgs = cmdArgs[1:]
   }
   ```

4. Add flag completion if the flag takes a discrete value set:
   ```go
   _ = cmd.RegisterFlagCompletionFunc("format", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
       return []string{"env", "json", "ini"}, cobra.ShellCompDirectiveNoFileComp
   })
   ```

5. If the command gets a test file, use the cobra Example-test template (see `cli/list_test.go`, `cli/add_test.go`, `cli/export_test.go`, `cli/exec_test.go`):
   ```go
   func ExampleNewCommand() {
       rootCmd := &cobra.Command{Use: "aws-vault"}
       rootCmd.SilenceUsage = true
       rootCmd.SilenceErrors = true
       awsVault := ConfigureGlobals(rootCmd)
       // awsVault.keyringImpl = ...
       rootCmd.AddCommand(ConfigureNewCommand(awsVault))
       rootCmd.SetArgs([]string{"new", "..."})
       _ = rootCmd.Execute()
       // Output:
       // ...
   }
   ```

6. Regenerate shell completions if you have them installed locally — cobra picks up new commands automatically, but verify:
   ```
   aws-vault completion zsh > ~/.oh-my-zsh/completions/_aws-vault  # or wherever
   ```

---

## 5. How to add a new global flag

Edit `cli/global.go` inside `ConfigureGlobals`. Use the appropriate `rootCmd.PersistentFlags()` call. Three templates:

**Plain flag with default**:
```go
rootCmd.PersistentFlags().StringVar(&a.Field, "name", "default", "description")
```

**Flag with env fallback** (mirrors kingpin's `.Envar()`):
```go
rootCmd.PersistentFlags().StringVar(&a.Field, "name",
    readEnvDefault("ENV_NAME", "fallback"),
    "description")
```

**Flag with env fallback + value-set completion**:
```go
rootCmd.PersistentFlags().StringVar(&a.KeyringBackend, "backend",
    readEnvDefault("AWS_VAULT_BACKEND", backendsAvailable[0]),
    fmt.Sprintf("Secret backend to use %v", backendsAvailable))
_ = rootCmd.RegisterFlagCompletionFunc("backend", func(...) ([]string, cobra.ShellCompDirective) {
    return backendsAvailable, cobra.ShellCompDirectiveNoFileComp
})
```

If the flag is an enum, add validation in `rootCmd.PersistentPreRunE` following the pattern used for `--backend` and `--prompt`. Silent regressions on enum validation is the main risk when translating from kingpin `.EnumVar()`.

---

## 6. Completion wrappers (shell-side)

The shipped shell completion in `contrib/completions/{bash,fish,zsh}/` is a **wrapper** that:

- Sources cobra's auto-generated completion as the base.
- Intercepts `--` on the command line and delegates to the wrapped command's completion (via `_command_offset`, `complete -C`, `_normal`).

If you change anything in `ConfigureExecCommand`'s positional handling (args/flags after profile), verify the delegation still works:

```zsh
aws-vault exec myprofile -- aws s3 <TAB>    # should show aws s3 subcommands
```

The delegation requires the wrapped command to have its own shell completion registered (e.g. `complete -C aws_completer aws` for AWS CLI v2).

---

## 7. Regression-prevention checklist

These were dropped in the original cobra migration (upstream PR #172) and had to be restored. Don't let them slip again.

- [ ] `--backend` validation: `PersistentPreRunE` must reject values not in `backendsAvailable`.
- [ ] `--prompt` validation: rejects `pass`, rejects values not in `promptsAvailable`.
- [ ] `AWS_VAULT_OP_TIMEOUT` env var: `--op-timeout` default must read from env.
- [ ] `--op-desktop-account-id` flag registered (added post-revert; don't lose on future merges).
- [ ] `--profile-env` flag on `exec` (added post-revert, PR #340).
- [ ] `SetInterspersed(false)` on `exec` — without it, flags after the profile get parsed as `exec`'s own flags instead of the wrapped command's.
- [ ] `--` separator stripping in `exec`'s `RunE` — cobra preserves `--` in args, unlike kingpin.
- [ ] Root command `RunE: cmd.Help()` — without it, bare `aws-vault` prints only the long description.

---

## 8. Reference files

- **Design spec**: `docs/superpowers/specs/2026-04-18-cobra-migration-design.md`
- **Implementation plan** (detailed task-by-task for the original migration): `docs/superpowers/plans/2026-04-18-cobra-migration.md`
- **Simplest command template**: `cli/clear.go` (29 lines of Configure function)
- **Most complex migration reference**: `cli/exec.go` (handles `--`, `SetInterspersed`, env var defaults, multiple flags)
- **Globals pattern**: `cli/global.go`'s `ConfigureGlobals` and `PersistentPreRunE`
- **Example test pattern**: `cli/list_test.go` (simplest) or `cli/exec_test.go` (with subprocess)
