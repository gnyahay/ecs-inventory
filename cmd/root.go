package cmd

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/anchore/ecs-inventory/internal/config"
	"github.com/anchore/ecs-inventory/pkg"
	"github.com/anchore/ecs-inventory/pkg/reporter"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "anchore-ecs-inventory",
	Short: "anchore-ecs-inventory tells Anchore which images are in use in your ECS clusters",
	Long:  "anchore-ecs-inventory can poll Amazon ECS (Elastic Container Service) APIs to tell Anchore which Images are currently in-use",
	Args:  cobra.MaximumNArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) > 0 {
			err := cmd.Help()
			if err != nil {
				log.Error("error running help command", err)
				os.Exit(1)
			}
			os.Exit(1)
		}
		log.Info("Starting anchore-ecs-inventory")

		// Region is optional. When no roles are assumed and no region is set, warn but continue -
		// the AWS SDK may still resolve a region from the environment or instance metadata.
		if appConfig.Region == "" && len(appConfig.AssumeRole) == 0 {
			log.Warn(
				"No region or assume-role configured; relying on AWS SDK default region resolution (e.g. AWS_REGION or instance metadata)",
			)
		}

		// Validate anchore connection & credentials, using a dummy report to post but this will be
		// replaced in the future with a health check endpoint for the agents
		if appConfig.AnchoreDetails.IsValid() {
			dummyReport := reporter.Report{
				ClusterARN: "validating-creds",
				Timestamp:  time.Now().UTC().Format(time.RFC3339),
			}
			err := reporter.Post(dummyReport, appConfig.AnchoreDetails)
			if err != nil {
				log.Error("Failed to validate connection to Anchore", err)
			} else {
				log.Info("Successfully validated connection to Anchore")
			}
		} else {
			log.Warn("Anchore details not specified, will not report inventory")
		}

		pkg.PeriodicallyGetInventoryReport(
			appConfig.PollingIntervalSeconds,
			appConfig.AnchoreDetails,
			appConfig.Region,
			appConfig.AssumeRole,
			appConfig.Quiet,
			appConfig.DryRun,
		)
	},
}

func init() {
	opt := "polling-interval-seconds"
	rootCmd.Flags().
		StringP(opt, "p", strconv.Itoa(config.DefaultConfigValues.PollingIntervalSeconds), "this specifies the polling interval of the ECS API in seconds")
	if err := viper.BindPFlag(opt, rootCmd.Flags().Lookup(opt)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", opt, err)
		os.Exit(1)
	}

	opt = "region"
	rootCmd.Flags().
		StringP(opt, "r", config.DefaultConfigValues.Region, "if set overrides the AWS_REGION environment variable/region specified in anchore-ecs-inventory config")
	if err := viper.BindPFlag(opt, rootCmd.Flags().Lookup(opt)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", opt, err)
		os.Exit(1)
	}

	opt = "quiet"
	rootCmd.Flags().
		BoolP(opt, "q", config.DefaultConfigValues.Quiet, "suppresses inventory report output to stdout")
	if err := viper.BindPFlag(opt, rootCmd.Flags().Lookup(opt)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", opt, err)
		os.Exit(1)
	}

	opt = "dry-run"
	rootCmd.Flags().
		BoolP(opt, "d", config.DefaultConfigValues.DryRun, "do not report inventory to Anchore")
	if err := viper.BindPFlag(opt, rootCmd.Flags().Lookup(opt)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", opt, err)
		os.Exit(1)
	}
}
