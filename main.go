package main

import (
	"fmt"
	"os"

	"github.com/byteness/aws-vault/v7/cli"
	"github.com/spf13/cobra"
)

// Version is provided at compile time
var Version = "dev"

func main() {
	rootCmd := &cobra.Command{
		Use:   "aws-vault",
		Short: "A vault for securely storing and accessing AWS credentials in development environments.",
		Long:  "A vault for securely storing and accessing AWS credentials in development environments.",
		Version: Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// Set version annotation
	rootCmd.Annotations = map[string]string{"version": Version}

	// Get the AwsVault instance for global flags
	a := cli.NewAwsVault()
	
	// Add global flags to root command
	cli.AddGlobalFlags(rootCmd, a)

	// Create and configure all subcommands
	rootCmd.AddCommand(cli.NewAddCommand(a))
	rootCmd.AddCommand(cli.NewRemoveCommand(a))
	rootCmd.AddCommand(cli.NewListCommand(a))
	rootCmd.AddCommand(cli.NewRotateCommand(a))
	rootCmd.AddCommand(cli.NewExecCommand(a))
	rootCmd.AddCommand(cli.NewExportCommand(a))
	rootCmd.AddCommand(cli.NewClearCommand(a))
	rootCmd.AddCommand(cli.NewLoginCommand(a))
	rootCmd.AddCommand(cli.NewProxyCommand())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
