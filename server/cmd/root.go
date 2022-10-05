package cmd

import (
	"server/server"

	"github.com/spf13/cobra"
)

var flags server.ServerFlags

// DIGD [--recursion=true] [--help]
var rootCmd = &cobra.Command{
	Use:   "digd",
	Short: "A Domain Name System local cache server",
	Long: `A Domain Name System local cache server.
For more information, please visit
	https://github.com/ligen131/CyberLighthouse`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {

	},
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
	s := server.Server{}
	s.Start(flags)
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&flags.IsRecursion, "recursion", true, "if true, server will query recursitively")
}
