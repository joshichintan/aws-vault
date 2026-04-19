package cli

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/byteness/aws-vault/v7/server"
	"github.com/spf13/cobra"
)

func ConfigureProxyCommand() *cobra.Command {
	stop := false

	cmd := &cobra.Command{
		Use:     "proxy",
		Aliases: []string{"server"},
		Short:   "Start a proxy for the ec2 instance role server locally",
		Long:    "Start a proxy for the ec2 instance role server locally.",
		Hidden:  true,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if stop {
				server.StopProxy()
				return nil
			}
			handleSigTerm()
			return server.StartProxy()
		},
	}

	cmd.Flags().BoolVar(&stop, "stop", false, "Stop the proxy")

	return cmd
}

func handleSigTerm() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		server.Shutdown()
		os.Exit(1)
	}()
}
