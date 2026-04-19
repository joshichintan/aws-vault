#compdef aws-vault
#
# zsh completion wrapper for aws-vault (cobra-based).
#
# Loads cobra's generated completion as the base, then wraps it so that
# after a `--` is seen on the command line (e.g. `aws-vault exec <profile> --`),
# completion is delegated to the wrapped command's own completion.
#
# Install:
#   Place this file on your $fpath as `_aws-vault`.
#   For oh-my-zsh users:
#     mkdir -p ~/.oh-my-zsh/completions
#     cp aws-vault.zsh ~/.oh-my-zsh/completions/_aws-vault
#     rm -f ~/.zcompdump
#
# Without this wrapper, `aws-vault completion zsh` gives you basic completion
# up through the profile name but no delegation after `--`.

# Pull in cobra's generated completion. It defines `_aws-vault` — rename it to
# `_aws-vault_cobra` and shadow it with the wrapper below.
if (( ! $+functions[_aws-vault_cobra] )); then
    eval "$(
        aws-vault completion zsh 2>/dev/null \
            | sed -E 's/^(_aws-vault)\(\)/_aws-vault_cobra()/'
    )"
fi

_aws-vault() {
    local i
    for (( i = 1; i <= ${#words[@]}; i++ )); do
        if [[ "${words[i]}" == "--" ]]; then
            # Strip everything up to and including the `--` and delegate to
            # zsh's normal command completion on the remainder.
            (( CURRENT -= i ))
            words=("${words[@]:i}")
            _normal
            return
        fi
    done

    _aws-vault_cobra "$@"
}

if [[ "$(basename -- ${(%):-%x})" != "_aws-vault" ]]; then
    compdef _aws-vault aws-vault
fi
