package cli

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/byteness/aws-vault/v7/server"
	"github.com/spf13/cobra"
)

func NewProxyCommand() *cobra.Command {
	var stop bool

	cmd := &cobra.Command{
		Use:    "proxy",
		Short:  "Start a proxy for the ec2 instance role server locally",
		Long:   "Start a proxy for the ec2 instance role server locally",
		Aliases: []string{"server"},
		Hidden: true,
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
	// shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		server.Shutdown()
		os.Exit(1)
	}()
}
