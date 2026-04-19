# bash completion wrapper for aws-vault (cobra-based).
#
# Loads cobra's generated completion as the base, then wraps it so that
# after a `--` is seen on the command line (e.g. `aws-vault exec <profile> --`),
# completion is delegated to the wrapped command's own completion via
# `_command_offset`.
#
# Install:
#   # macOS (homebrew):
#   cp aws-vault.bash "$(brew --prefix)/etc/bash_completion.d/aws-vault"
#   # Linux:
#   cp aws-vault.bash /etc/bash_completion.d/aws-vault
#   # Or source from ~/.bashrc:
#   source /path/to/aws-vault.bash
#
# Without this wrapper, `aws-vault completion bash` gives you basic completion
# up through the profile name but no delegation after `--`.

# Source cobra's generated bash completion; it will register its own handler
# for aws-vault via `complete -F`. We then override that registration below.
if command -v aws-vault >/dev/null 2>&1; then
    source <(aws-vault completion bash)
fi

_aws-vault_delegate_or_cobra() {
    local i
    for (( i=1; i < COMP_CWORD; i++ )); do
        if [[ "${COMP_WORDS[i]}" == "--" ]]; then
            # Delegate to the wrapped command's completion starting from
            # the word after `--`.
            _command_offset $((i + 1))
            return
        fi
    done

    # No `--` seen — call cobra's registered completion function. Cobra's
    # bash completion registers a function named __start_aws-vault.
    __start_aws-vault
}

# Override cobra's registration with our wrapper. `-o default` falls back to
# file completion if the wrapper returns nothing.
complete -F _aws-vault_delegate_or_cobra -o default aws-vault
