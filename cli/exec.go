package cli

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	osexec "os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/spf13/cobra"
	"github.com/byteness/aws-vault/v7/iso8601"
	"github.com/byteness/aws-vault/v7/server"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

type ExecCommandInput struct {
	ProfileName      string
	Command          string
	Args             []string
	StartEc2Server   bool
	StartEcsServer   bool
	Lazy             bool
	JSONDeprecated   bool
	Config           vault.ProfileConfig
	SessionDuration  time.Duration
	NoSession        bool
	UseStdout        bool
	ShowHelpMessages bool
	UseProfileEnv    bool
}

func (input ExecCommandInput) validate() error {
	if input.StartEc2Server && input.StartEcsServer {
		return fmt.Errorf("Can't use --ec2-server with --ecs-server")
	}
	if input.StartEc2Server && input.JSONDeprecated {
		return fmt.Errorf("Can't use --ec2-server with --json")
	}
	if input.StartEc2Server && input.NoSession {
		return fmt.Errorf("Can't use --ec2-server with --no-session")
	}
	if input.StartEcsServer && input.JSONDeprecated {
		return fmt.Errorf("Can't use --ecs-server with --json")
	}
	if input.StartEcsServer && input.NoSession {
		return fmt.Errorf("Can't use --ecs-server with --no-session")
	}
	if input.StartEcsServer && input.Config.MfaPromptMethod == "terminal" {
		return fmt.Errorf("Can't use --prompt=terminal with --ecs-server. Specify a different prompt driver")
	}
	if input.StartEc2Server && input.Config.MfaPromptMethod == "terminal" {
		return fmt.Errorf("Can't use --prompt=terminal with --ec2-server. Specify a different prompt driver")
	}

	return nil
}

func hasBackgroundServer(input ExecCommandInput) bool {
	return input.StartEcsServer || input.StartEc2Server
}

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
			if len(args) == 1 {
				// After the profile, suggest `--` so users can delegate to the
				// wrapped command's own shell completion. The shipped zsh/bash/fish
				// completion scripts in contrib/ intercept `--` and hand off to
				// the real command's completion function.
				return []string{"--"}, cobra.ShellCompDirectiveNoFileComp
			}
			return nil, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				input.ProfileName = args[0]
			}
			// Skip "--" separator if present (used to separate aws-vault args from wrapped command args)
			cmdArgs := args[1:]
			if len(cmdArgs) > 0 && cmdArgs[0] == "--" {
				cmdArgs = cmdArgs[1:]
			}
			if len(cmdArgs) > 0 {
				input.Command = cmdArgs[0]
				input.Args = cmdArgs[1:]
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

func ExecCommand(input ExecCommandInput, f *vault.ConfigFile, keyring keyring.Keyring) (exitcode int, err error) {
	if os.Getenv("AWS_VAULT") != "" {
		return 0, fmt.Errorf("running in an existing aws-vault subshell; 'exit' from the subshell or unset AWS_VAULT to force")
	}

	if err := input.validate(); err != nil {
		return 0, err
	}

	config, err := vault.NewConfigLoader(input.Config, f, input.ProfileName).GetProfileConfig(input.ProfileName)
	if err != nil {
		return 0, fmt.Errorf("Error loading config: %w", err)
	}

	credsProvider, err := vault.NewTempCredentialsProvider(config, &vault.CredentialKeyring{Keyring: keyring}, input.NoSession, false)
	if err != nil {
		return 0, fmt.Errorf("Error getting temporary credentials: %w", err)
	}

	subshellHelp := ""
	if input.Command == "" {
		input.Command = getDefaultShell()
		subshellHelp = fmt.Sprintf("Starting subshell %s, use `exit` to exit the subshell", input.Command)
	}

	cmdEnv := createEnv(input.ProfileName, config.Region, config.EndpointURL)

	if input.StartEc2Server {
		if server.IsProxyRunning() {
			return 0, fmt.Errorf("Another process is already bound to 169.254.169.254:80")
		}

		printHelpMessage("Warning: Starting a local EC2 credential server on 169.254.169.254:80; AWS credentials will be accessible to any process while it is running", input.ShowHelpMessages)
		if err := server.StartEc2EndpointProxyServerProcess(); err != nil {
			return 0, err
		}
		defer server.StopProxy()

		if err = server.StartEc2CredentialsServer(context.TODO(), credsProvider, config.Region); err != nil {
			return 0, fmt.Errorf("Failed to start credential server: %w", err)
		}
		printHelpMessage(subshellHelp, input.ShowHelpMessages)
	} else if input.StartEcsServer {
		printHelpMessage("Starting a local ECS credential server; your app's AWS sdk must support AWS_CONTAINER_CREDENTIALS_FULL_URI.", input.ShowHelpMessages)
		if err = startEcsServerAndSetEnv(credsProvider, config, input.Lazy, &cmdEnv); err != nil {
			return 0, err
		}
		printHelpMessage(subshellHelp, input.ShowHelpMessages)
	} else {
		if input.UseProfileEnv {
			// Validate credentials are accessible before setting AWS_PROFILE,
			// so we fail fast rather than letting the child process fail silently.
			if _, err = credsProvider.Retrieve(context.TODO()); err != nil {
				return 0, fmt.Errorf("failed to get credentials for %s: %w", input.ProfileName, err)
			}
			if config.HasSSOStartURL() {
				if err = vault.SyncOIDCTokenToStandardCache(config, keyring); err != nil {
					log.Printf("Warning: failed to sync OIDC token to standard cache: %s", err)
				}
			}
			cmdEnv.Set("AWS_PROFILE", input.ProfileName)
		} else {
			if err = addCredsToEnv(credsProvider, input.ProfileName, &cmdEnv); err != nil {
				return 0, err
			}
		}
		printHelpMessage(subshellHelp, input.ShowHelpMessages)

		err = doExecSyscall(input.Command, input.Args, cmdEnv) // will not return if exec syscall succeeds
		if err != nil {
			log.Println("Error doing execve syscall:", err.Error())
			log.Println("Falling back to running a subprocess")
		}
	}

	return runSubProcess(input.Command, input.Args, cmdEnv)
}

func printHelpMessage(helpMsg string, showHelpMessages bool) {
	if helpMsg != "" {
		if showHelpMessages {
			printToStderr(helpMsg)
		} else {
			log.Println(helpMsg)
		}
	}
}

func printToStderr(helpMsg string) {
	fmt.Fprint(os.Stderr, helpMsg, "\n")
}

func createEnv(profileName string, region string, endpointURL string) environ {
	env := environ(os.Environ())
	env.Unset("AWS_ACCESS_KEY_ID")
	env.Unset("AWS_SECRET_ACCESS_KEY")
	env.Unset("AWS_SESSION_TOKEN")
	env.Unset("AWS_SECURITY_TOKEN")
	env.Unset("AWS_CREDENTIAL_FILE")
	env.Unset("AWS_DEFAULT_PROFILE")
	env.Unset("AWS_PROFILE")
	env.Unset("AWS_SDK_LOAD_CONFIG")

	env.Set("AWS_VAULT", profileName)

	if region != "" {
		// AWS_REGION is used by most SDKs. But boto3 (Python SDK) uses AWS_DEFAULT_REGION
		// See https://docs.aws.amazon.com/sdkref/latest/guide/feature-region.html
		log.Printf("Setting subprocess env: AWS_REGION=%s, AWS_DEFAULT_REGION=%s", region, region)
		env.Set("AWS_REGION", region)
		env.Set("AWS_DEFAULT_REGION", region)
	}

	if endpointURL != "" {
		log.Printf("Setting subprocess env: AWS_ENDPOINT_URL=%s", endpointURL)
		env.Set("AWS_ENDPOINT_URL", endpointURL)
	}

	return env
}

func startEcsServerAndSetEnv(credsProvider aws.CredentialsProvider, config *vault.ProfileConfig, lazy bool, cmdEnv *environ) error {
	ecsServer, err := server.NewEcsServer(context.TODO(), credsProvider, config, "", 0, lazy)
	if err != nil {
		return err
	}
	go func() {
		err = ecsServer.Serve()
		if err != http.ErrServerClosed { // ErrServerClosed is a graceful close
			log.Fatalf("ecs server: %s", err.Error())
		}
	}()

	log.Println("Setting subprocess env AWS_CONTAINER_CREDENTIALS_FULL_URI, AWS_CONTAINER_AUTHORIZATION_TOKEN")
	cmdEnv.Set("AWS_CONTAINER_CREDENTIALS_FULL_URI", ecsServer.BaseURL())
	cmdEnv.Set("AWS_CONTAINER_AUTHORIZATION_TOKEN", ecsServer.AuthToken())

	return nil
}

func addCredsToEnv(credsProvider aws.CredentialsProvider, profileName string, cmdEnv *environ) error {
	creds, err := credsProvider.Retrieve(context.TODO())
	if err != nil {
		return fmt.Errorf("Failed to get credentials for %s: %w", profileName, err)
	}

	log.Println("Setting subprocess env: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY")
	cmdEnv.Set("AWS_ACCESS_KEY_ID", creds.AccessKeyID)
	cmdEnv.Set("AWS_SECRET_ACCESS_KEY", creds.SecretAccessKey)

	if creds.SessionToken != "" {
		log.Println("Setting subprocess env: AWS_SESSION_TOKEN")
		cmdEnv.Set("AWS_SESSION_TOKEN", creds.SessionToken)
	}
	if creds.CanExpire {
		log.Println("Setting subprocess env: AWS_CREDENTIAL_EXPIRATION")
		cmdEnv.Set("AWS_CREDENTIAL_EXPIRATION", iso8601.Format(creds.Expires))
	}

	return nil
}

// environ is a slice of strings representing the environment, in the form "key=value".
type environ []string

// Unset an environment variable by key
func (e *environ) Unset(key string) {
	for i := range *e {
		if strings.HasPrefix((*e)[i], key+"=") {
			(*e)[i] = (*e)[len(*e)-1]
			*e = (*e)[:len(*e)-1]
			break
		}
	}
}

// Set adds an environment variable, replacing any existing ones of the same key
func (e *environ) Set(key, val string) {
	e.Unset(key)
	*e = append(*e, key+"="+val)
}

func getDefaultShell() string {
	command := os.Getenv("SHELL")
	if command == "" {
		if runtime.GOOS == "windows" {
			command = "cmd.exe"
		} else {
			command = "/bin/sh"
		}
	}
	return command
}

func runSubProcess(command string, args []string, env []string) (int, error) {
	log.Printf("Starting a subprocess: %s %s", command, strings.Join(args, " "))

	cmd := osexec.Command(command, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan)

	if err := cmd.Start(); err != nil {
		return 0, err
	}

	// proxy signals to process
	go func() {
		for {
			sig := <-sigChan
			_ = cmd.Process.Signal(sig)
		}
	}()

	if err := cmd.Wait(); err != nil {
		_ = cmd.Process.Signal(os.Kill)
		return 0, fmt.Errorf("Failed to wait for command termination: %v", err)
	}

	waitStatus := cmd.ProcessState.Sys().(syscall.WaitStatus)

	return waitStatus.ExitStatus(), nil
}

func doExecSyscall(command string, args []string, env []string) error {
	log.Printf("Exec command %s %s", command, strings.Join(args, " "))

	argv0, err := osexec.LookPath(command)
	if err != nil {
		return fmt.Errorf("Couldn't find the executable '%s': %w", command, err)
	}

	log.Printf("Found executable %s", argv0)

	argv := make([]string, 0, 1+len(args))
	argv = append(argv, command)
	argv = append(argv, args...)

	return syscall.Exec(argv0, argv, env)
}
