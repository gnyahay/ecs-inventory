package pkg

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/anchore/ecs-inventory/internal/config"
	"github.com/anchore/ecs-inventory/pkg/connection"
	"github.com/anchore/ecs-inventory/pkg/inventory"
	"github.com/anchore/ecs-inventory/pkg/logger"
)

var log logger.Logger

// inventoryPass describes a single account-region gather: which region to query and, optionally,
// which role to assume first.
type inventoryPass struct {
	region        string
	assumeRoleARN string
	externalID    string
}

// buildInventoryPasses turns the region + assume-role configuration into the set of gathers to run
// each polling cycle. With no roles configured this is a single pass against the agent's own
// account using region; with roles configured it is one pass per role (each with its own region).
func buildInventoryPasses(region string, assumeRoles []config.AssumeRoleConfig) []inventoryPass {
	if len(assumeRoles) == 0 {
		return []inventoryPass{{region: region}}
	}
	passes := make([]inventoryPass, 0, len(assumeRoles))
	for _, role := range assumeRoles {
		passes = append(passes, inventoryPass{
			region:        role.Region,
			assumeRoleARN: role.RoleARN,
			externalID:    role.ExternalID,
		})
	}
	return passes
}

// PeriodicallyGetInventoryReport periodically retrieves image results and reports/outputs them
// according to the configuration.
//
// Before entering the poll loop it runs a startup pre-flight: every configured pass must be able to
// obtain AWS credentials (for assume-role entries this performs the STS AssumeRole). If any entry
// fails, the function returns an error so the process can exit and the misconfiguration is surfaced
// immediately, rather than silently under-reporting. Once the loop is running, per-cycle failures do
// NOT exit — they are logged and the next cycle retries — so a role that breaks after startup never
// crashloops the agent into monitoring nothing.
func PeriodicallyGetInventoryReport(
	pollingIntervalSeconds int,
	anchoreDetails connection.AnchoreInfo,
	region string,
	assumeRoles []config.AssumeRoleConfig,
	quiet, dryRun bool,
) error {
	// Build each pass's AWS config once and reuse it across poll cycles. The assume-role
	// credentials cache lives inside the config, so reusing it lets credentials refresh over the
	// daemon's lifetime rather than issuing a fresh AssumeRole every cycle.
	ctx := context.Background()
	type readyPass struct {
		region        string
		assumeRoleARN string
		cfg           aws.Config
	}
	var passes []readyPass
	failed := 0
	for _, pass := range buildInventoryPasses(region, assumeRoles) {
		cfg, err := inventory.BuildAWSConfig(ctx, pass.region, pass.assumeRoleARN, pass.externalID)
		if err == nil {
			// Force credential resolution now so a misconfigured/unauthorized entry (bad role ARN,
			// wrong external ID, un-granted cross-account role, missing base credentials) fails at
			// startup instead of on the first poll cycle.
			_, err = cfg.Credentials.Retrieve(ctx)
		}
		if err != nil {
			failed++
			log.Error("Assume-role pre-flight validation failed for entry", err,
				"region", pass.region, "assumedRole", pass.assumeRoleARN)
			continue
		}
		passes = append(passes, readyPass{region: pass.region, assumeRoleARN: pass.assumeRoleARN, cfg: cfg})
	}
	if failed > 0 {
		return fmt.Errorf(
			"assume-role pre-flight validation failed: %d of %d configured entr(ies) could not obtain credentials; "+
				"fix the configuration/permissions and restart", failed, failed+len(passes))
	}
	log.Info("Assume-role pre-flight validation passed", "entries", len(passes))

	// Fire off a ticker that reports according to a configurable polling interval
	ticker := time.NewTicker(time.Duration(pollingIntervalSeconds) * time.Second)

	for {
		for _, pass := range passes {
			err := inventory.GetInventoryReportsForRegion(pass.cfg, pass.region, pass.assumeRoleARN, anchoreDetails, quiet, dryRun)
			if err != nil {
				// Runtime failures are logged and tolerated: the next cycle retries, and other
				// passes keep reporting. We deliberately do NOT exit here.
				log.Error("Failed to get Inventory Reports for region", err,
					"region", pass.region, "assumedRole", pass.assumeRoleARN)
			}
		}

		// Wait at least as long as the ticker
		log.Debugf("Start new gather %s", <-ticker.C)
	}
}

func SetLogger(logger logger.Logger) {
	log = logger
}
