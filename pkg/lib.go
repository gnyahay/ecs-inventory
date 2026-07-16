package pkg

import (
	"time"

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

// PeriodicallyGetInventoryReport periodically retrieve image results and report/output them according to the configuration.
// Note: Errors do not cause the function to exit, since this is periodically running
func PeriodicallyGetInventoryReport(
	pollingIntervalSeconds int,
	anchoreDetails connection.AnchoreInfo,
	region string,
	assumeRoles []config.AssumeRoleConfig,
	quiet, dryRun bool,
) {
	passes := buildInventoryPasses(region, assumeRoles)

	// Fire off a ticker that reports according to a configurable polling interval
	ticker := time.NewTicker(time.Duration(pollingIntervalSeconds) * time.Second)

	for {
		for _, pass := range passes {
			err := inventory.GetInventoryReportsForRegion(pass.region, pass.assumeRoleARN, pass.externalID, anchoreDetails, quiet, dryRun)
			if err != nil {
				log.Error("Failed to get Inventory Reports for region", err)
			}
		}

		// Wait at least as long as the ticker
		log.Debugf("Start new gather %s", <-ticker.C)
	}
}

func SetLogger(logger logger.Logger) {
	log = logger
}
