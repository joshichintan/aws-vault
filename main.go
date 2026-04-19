package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/byteness/aws-vault/v7/cli"
	"github.com/spf13/cobra"
)

// Version is provided at compile time
var Version = "dev"

// Shell-specific delegation wrappers appended to cobra's auto-generated
// completion output. Together they implement the post-`--` behavior:
// when the command line contains `--` (as in `aws-vault exec <profile> --
// aws s3 ls`), completion is handed off to the wrapped command's own
// completion function. Without these, cobra treats everything after `--`
// as opaque args and provides no completion for them.
const zshDelegationWrapper = `
# aws-vault: post-"--" delegation (added by main.go)
# After cobra's _aws-vault() has been defined above, we rename it to
# _aws-vault_cobra, then redefine _aws-vault as a wrapper that intercepts
# "--" and delegates to zsh's _normal command completion.
if (( $+functions[_aws-vault] )) && ! (( $+functions[_aws-vault_cobra] )); then
    eval "_aws-vault_cobra() ${functions[_aws-vault]}"
    _aws-vault() {
        local i
        for (( i = 2; i <= CURRENT; i++ )); do
            if [[ "${words[i]}" == "--" ]]; then
                shift $i words
                (( CURRENT -= i ))
                _normal
                return
            fi
        done
        _aws-vault_cobra "$@"
    }
fi
`

const bashDelegationWrapper = `
# aws-vault: post-"--" delegation (added by main.go)
# Override cobra's `+"`complete -F __start_aws-vault`"+` with a wrapper that
# intercepts "--" and delegates to bash's _command_offset for the wrapped
# command. If no "--" is present, fall through to cobra's __start_aws-vault.
_aws-vault_delegate() {
    local i
    for (( i=1; i < COMP_CWORD; i++ )); do
        if [[ "${COMP_WORDS[i]}" == "--" ]]; then
            _command_offset $((i + 1))
            return
        fi
    done
    __start_aws-vault
}
complete -F _aws-vault_delegate -o default aws-vault
`

const fishDelegationWrapper = `
# aws-vault: post-"--" delegation (added by main.go)
# Register a higher-priority completion that fires only when the command
# line contains "--", delegating to the wrapped command's completion via
# `+"`complete -C`"+`.
function __aws_vault_has_double_dash
    string match -q -r ' -- ' -- (commandline -pc)
end

function __aws_vault_delegate_after_dash
    set -l parts (string split --max 1 ' -- ' -- (commandline -pc))
    if test (count $parts) -ge 2
        complete -C "$parts[2]"
    end
end

complete -c aws-vault -n '__aws_vault_has_double_dash' -xa '(__aws_vault_delegate_after_dash)'
`

func main() {
	rootCmd := &cobra.Command{
		Use:   "aws-vault",
		Short: "A vault for securely storing and accessing AWS credentials in development environments",
		Long:  "A vault for securely storing and accessing AWS credentials in development environments.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	rootCmd.Version = Version
	rootCmd.SetVersionTemplate("{{.Version}}\n")

	a := cli.ConfigureGlobals(rootCmd)
	rootCmd.AddCommand(cli.ConfigureClearCommand(a))
	rootCmd.AddCommand(cli.ConfigureListCommand(a))
	rootCmd.AddCommand(cli.ConfigureRemoveCommand(a))
	rootCmd.AddCommand(cli.ConfigureAddCommand(a))
	rootCmd.AddCommand(cli.ConfigureRotateCommand(a))
	rootCmd.AddCommand(cli.ConfigureLoginCommand(a))
	rootCmd.AddCommand(cli.ConfigureExportCommand(a))
	rootCmd.AddCommand(cli.ConfigureProxyCommand())
	rootCmd.AddCommand(cli.ConfigureExecCommand(a))

	// Replace cobra's auto-generated completion subcommand with one that
	// appends the post-`--` delegation wrapper to the generated output.
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.AddCommand(&cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion script",
		Long: `Generate a shell completion script, including post-"--" delegation
to the wrapped command's own completion (so, e.g.,
` + "`aws-vault exec <profile> -- aws s3 <TAB>`" + ` fires aws's completion).

To load completions:

  # zsh (write once, then restart shell):
  aws-vault completion zsh > "${fpath[1]}/_aws-vault"

  # bash (homebrew on macOS):
  aws-vault completion bash > "$(brew --prefix)/etc/bash_completion.d/aws-vault"

  # fish:
  aws-vault completion fish > ~/.config/fish/completions/aws-vault.fish

  # powershell (no delegation — aws-vault prints just cobra's default):
  aws-vault completion powershell | Out-String | Invoke-Expression

For the bash/zsh/fish delegation to actually complete the wrapped command,
that command's own completer must be registered. Most tools ship it — for
AWS CLI v2 on zsh: "autoload -Uz bashcompinit && bashcompinit && complete -C aws_completer aws".`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			var buf bytes.Buffer
			root := cmd.Root()
			switch args[0] {
			case "zsh":
				if err := root.GenZshCompletion(&buf); err != nil {
					return err
				}
				if _, err := os.Stdout.WriteString(buf.String()); err != nil {
					return err
				}
				_, err := os.Stdout.WriteString(zshDelegationWrapper)
				return err
			case "bash":
				if err := root.GenBashCompletionV2(&buf, true); err != nil {
					return err
				}
				if _, err := os.Stdout.WriteString(buf.String()); err != nil {
					return err
				}
				_, err := os.Stdout.WriteString(bashDelegationWrapper)
				return err
			case "fish":
				if err := root.GenFishCompletion(&buf, true); err != nil {
					return err
				}
				if _, err := os.Stdout.WriteString(buf.String()); err != nil {
					return err
				}
				_, err := os.Stdout.WriteString(fishDelegationWrapper)
				return err
			case "powershell":
				return root.GenPowerShellCompletionWithDesc(os.Stdout)
			}
			return fmt.Errorf("unknown shell: %s", strings.Join(args, " "))
		},
	})

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
