# fish completion wrapper for aws-vault (cobra-based).
#
# Sources cobra's generated fish completion as the base, then layers on `--`
# delegation so that after `aws-vault exec <profile> --` the completion is
# handed off to the wrapped command's own completion via `complete -C`.
#
# Install:
#   cp aws-vault.fish ~/.config/fish/completions/aws-vault.fish
#
# Without this wrapper, `aws-vault completion fish` gives you basic completion
# up through the profile name but no delegation after `--`.

if status --is-interactive
    # Load cobra's generated fish completion as the base layer.
    if command -q aws-vault
        aws-vault completion fish | source
    end

    # Layer a higher-priority `-x` completion that fires when `--` is on the
    # command line. When it matches, delegate to the wrapped command.
    complete -c aws-vault -n '__fish_aws_vault_saw_double_dash' -xa '(__fish_aws_vault_delegate)'

    function __fish_aws_vault_saw_double_dash
        string match -q -r ' -- ' -- (commandline -pc)
    end

    function __fish_aws_vault_delegate
        # Split at the first `--`; delegate completion to the portion after it.
        set -l parts (string split --max 1 ' -- ' -- (commandline -pc))
        if test (count $parts) -ge 2
            complete -C "$parts[2]"
        end
    end
end
