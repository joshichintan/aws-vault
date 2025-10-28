package cli

import (
	"log"
	"os"

	"github.com/spf13/cobra"
)

func ExampleAddCommand() {
	f, err := os.CreateTemp("", "aws-config")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(f.Name())

	os.Setenv("AWS_CONFIG_FILE", f.Name())
	os.Setenv("AWS_ACCESS_KEY_ID", "llamas")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "rock")
	os.Setenv("AWS_VAULT_BACKEND", "file")
	os.Setenv("AWS_VAULT_FILE_PASSPHRASE", "password")

	defer os.Unsetenv("AWS_ACCESS_KEY_ID")
	defer os.Unsetenv("AWS_SECRET_ACCESS_KEY")
	defer os.Unsetenv("AWS_VAULT_BACKEND")
	defer os.Unsetenv("AWS_VAULT_FILE_PASSPHRASE")

	rootCmd := &cobra.Command{Use: "aws-vault"}
	a := ConfigureGlobals(rootCmd)
	rootCmd.AddCommand(ConfigureAddCommand(a))
	rootCmd.SetArgs([]string{"add", "--debug", "--env", "foo"})
	_ = rootCmd.Execute()

	// Output:
	// Added credentials to profile "foo" in vault
}
