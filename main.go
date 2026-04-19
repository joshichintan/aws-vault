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

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
