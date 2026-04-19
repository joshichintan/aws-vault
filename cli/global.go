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

	opTimeoutDefault := 15 * time.Second
	if s := os.Getenv("AWS_VAULT_OP_TIMEOUT"); s != "" {
		if d, err := time.ParseDuration(s); err == nil {
			opTimeoutDefault = d
		}
	}
	rootCmd.PersistentFlags().DurationVar(&a.KeyringConfig.OPTimeout, "op-timeout", opTimeoutDefault,
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

		validBackend := false
		for _, v := range backendsAvailable {
			if v == a.KeyringBackend {
				validBackend = true
				break
			}
		}
		if !validBackend {
			return fmt.Errorf("--backend value must be one of %s, got '%s'", strings.Join(backendsAvailable, ","), a.KeyringBackend)
		}

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
