package cmd

import (
	"client/client"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var cfgFile string
var flags client.ClientFlags

// DIGG [A/NS/CNAME/AAAA/MX domain]/[domain] [--server=8.8.8.8] [--recursion=true] [--help]
var rootCmd = &cobra.Command{
	Use:   "digg",
	Short: "A Domain Name System query client",
	Long: `A Domain Name System query client, likes dig command in linux.
For more information, please visit
	https://github.com/ligen131/CyberLighthouse`,
	Args: func(cmd *cobra.Command, args []string) error {
		size := len(args)
		if size > 2 {
			return errors.New("too many arguments")
		}
		if size == 2 {
			args[0] = strings.ToLower(args[0])
			if args[0] != "a" && args[0] != "ns" && args[0] != "cname" && args[0] != "aaaa" && args[0] != "mx" {
				return fmt.Errorf("%s record is not supported", args[0])
			}
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		size := len(args)
		if size == 0 {
			flags.OriginFlags.Record = "a"
			flags.OriginFlags.Url = ""
		} else if size == 1 {
			flags.OriginFlags.Record = "a"
			flags.OriginFlags.Url = args[0]
		} else {
			flags.OriginFlags.Record = strings.ToLower(args[0])
			flags.OriginFlags.Url = args[1]
		}
		flags.ParseFlags()
		var c client.Client
		fmt.Println(c.Query(&flags))
	},
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	// cobra.OnInitialize(initConfig)
	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.digg.yaml)")
	rootCmd.PersistentFlags().StringVar(&flags.OriginFlags.Server, "server", "8.8.8.8", "DNS server for querying")
	rootCmd.PersistentFlags().BoolVar(&flags.OriginFlags.IsRecursion, "recursion", true, "if true, server will query recursitively")
	// rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// func initConfig() {
// 	if cfgFile != "" {
// 		viper.SetConfigFile(cfgFile)
// 	} else {
// 		home, err := os.UserHomeDir()
// 		cobra.CheckErr(err)

// 		viper.AddConfigPath(home)
// 		viper.SetConfigType("yaml")
// 		viper.SetConfigName(".digg")
// 	}

// 	viper.AutomaticEnv()

// 	if err := viper.ReadInConfig(); err == nil {
// 		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
// 	}
// }
