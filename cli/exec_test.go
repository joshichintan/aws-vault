package cli

import (
	"github.com/alecthomas/kingpin/v2"
	"github.com/byteness/keyring"
	"github.com/spf13/cobra"
)

func ExampleExecCommand() {
	app := kingpin.New("aws-vault", "")
	rootCmd := &cobra.Command{Use: "aws-vault"}
	awsVault := ConfigureGlobals(rootCmd)
	awsVault.keyringImpl = keyring.NewArrayKeyring([]keyring.Item{
		{Key: "llamas", Data: []byte(`{"AccessKeyID":"ABC","SecretAccessKey":"XYZ"}`)},
	})
	ConfigureExecCommand(app, awsVault)
	kingpin.MustParse(app.Parse([]string{
		"exec", "--no-session", "llamas", "--", "sh", "-c", "echo $AWS_ACCESS_KEY_ID",
	}))

	// Output:
	// ABC
}
