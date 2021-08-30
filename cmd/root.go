package cmd

import (
	"github.com/spf13/cobra"
	"github.com/wal-g/tracelog"
)


var rootCmd = &cobra.Command{
	Use: "spqr run --config `config-path`",
	Short: "SPQR",
	Long: "Stateless Postgres Query Router",
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd:   true,
	},
	SilenceUsage: true,
	SilenceErrors: true,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		tracelog.ErrorLogger.Fatal(err)
	}
}