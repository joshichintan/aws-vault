package cli

import (
	"github.com/alecthomas/kingpin/v2"
	"github.com/byteness/keyring"
	"github.com/spf13/cobra"
)

func ExampleListCommand() {
	app := kingpin.New("aws-vault", "")
	rootCmd := &cobra.Command{Use: "aws-vault"}
	awsVault := ConfigureGlobals(rootCmd)
	awsVault.keyringImpl = keyring.NewArrayKeyring([]keyring.Item{
		{Key: "llamas", Data: []byte(`{"AccessKeyID":"ABC","SecretAccessKey":"XYZ"}`)},
	})
	ConfigureListCommand(app, awsVault)
	kingpin.MustParse(app.Parse([]string{
		"list", "--credentials",
	}))

	// Output:
	// llamas
}
