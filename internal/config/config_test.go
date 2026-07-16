package config

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/ecs-inventory/pkg/connection"
)

func TestLoadConfigFromFileCliConfigPath(t *testing.T) {
	t.Cleanup(cleanup)

	cliOpts := CliOnlyOptions{
		ConfigPath: "testdata/config.yaml",
	}
	appCfg, err := LoadConfigFromFile(viper.GetViper(), &cliOpts)

	assert.NoError(t, err)

	expectedCfg := &AppConfig{
		CliOptions: CliOnlyOptions{
			ConfigPath: "testdata/config.yaml",
		},
		Log: Logging{
			Level:        "info",
			FileLocation: "/var/log/anchore-ecs-inventory.log",
		},
		AnchoreDetails: connection.AnchoreInfo{
			Account:  "admin",
			User:     "admin",
			Password: "foobar",
			URL:      "http://localhost:8228",
			HTTP: connection.HTTPConfig{
				Insecure:       false,
				TimeoutSeconds: 10,
			},
		},
		Region:                 "us-east-1",
		PollingIntervalSeconds: 60,
		Quiet:                  true,
	}

	assert.EqualValues(t, expectedCfg, appCfg)
}

func TestLoadConfigFromFileBadCliConfig(t *testing.T) {
	t.Cleanup(cleanup)

	cliOpts := CliOnlyOptions{
		ConfigPath: "testdata/bad-config.yaml",
	}
	_, err := LoadConfigFromFile(viper.GetViper(), &cliOpts)

	assert.Error(t, err)
}

func TestReadConfigNoConfigsPresent(t *testing.T) {
	t.Cleanup(cleanup)

	err := readConfig(viper.GetViper(), "", "anchore-ecs-inventory-but-not-really-lets-break-this-test")

	assert.Error(t, err)
}

func TestPasswordsAreObfuscated(t *testing.T) {
	t.Cleanup(cleanup)

	config := AppConfig{
		Log: Logging{},
		CliOptions: CliOnlyOptions{
			ConfigPath: "testdata/config.yaml",
		},
		PollingIntervalSeconds: 300,
		AnchoreDetails: connection.AnchoreInfo{
			URL:      "http://localhost:8228/v1",
			User:     "admin",
			Password: "foobar",
			Account:  "admin",
			HTTP:     connection.HTTPConfig{},
		},
	}

	expected := `log:
  level: ""
  filelocation: ""
clioptions:
  configpath: testdata/config.yaml
  verbosity: 0
pollingintervalseconds: 300
anchoredetails:
  url: http://localhost:8228/v1
  user: admin
  password: '******'
  account: admin
  http:
    insecure: false
    timeoutseconds: 0
region: ""
assumerole: []
quiet: false
dryrun: false
`

	assert.Equal(t, expected, config.String())
}

func TestDefaultValuesSuppliedForEmptyConfig(t *testing.T) {
	t.Cleanup(cleanup)

	configPath := "testdata/empty_config.yaml"

	cliOpts := CliOnlyOptions{
		ConfigPath: configPath,
	}

	appCfg, err := LoadConfigFromFile(viper.GetViper(), &cliOpts)
	assert.NoError(t, err)

	expectedCfg := &AppConfig{
		CliOptions: CliOnlyOptions{
			ConfigPath: configPath,
		},
		Log: Logging{
			Level: "info",
		},
		AnchoreDetails: connection.AnchoreInfo{
			Account:  "admin",
			Password: "",
			HTTP: connection.HTTPConfig{
				Insecure:       false,
				TimeoutSeconds: 60,
			},
		},
	}

	assert.EqualValues(t, expectedCfg, appCfg)
}

func TestCliOptsOverrideConfigFileOpts(t *testing.T) {
	t.Cleanup(cleanup)

	expectedRegion := "eu-west-2"
	cliOpts := CliOnlyOptions{
		ConfigPath: "testdata/config.yaml",
	}

	viper.Set("Region", expectedRegion)

	// Config file is set to "us-east-1"
	appCfg, err := LoadConfigFromFile(viper.GetViper(), &cliOpts)

	assert.NoError(t, err)
	assert.Equal(t, expectedRegion, appCfg.Region)
}

func TestAssumeRoleListParsedFromFile(t *testing.T) {
	t.Cleanup(cleanup)

	cliOpts := CliOnlyOptions{
		ConfigPath: "testdata/assume-role-config.yaml",
	}
	appCfg, err := LoadConfigFromFile(viper.GetViper(), &cliOpts)

	assert.NoError(t, err)
	assert.Equal(t, []AssumeRoleConfig{
		{RoleARN: "arn:aws:iam::111111111111:role/a", ExternalID: "ext-a", Region: "us-west-2"},
		{RoleARN: "arn:aws:iam::222222222222:role/b", Region: "eu-west-1"},
	}, appCfg.AssumeRole)
}

func TestAssumeRoleEntryRequiresRoleARN(t *testing.T) {
	t.Cleanup(cleanup)

	cfg := AppConfig{
		AssumeRole: []AssumeRoleConfig{
			{Region: "us-west-2"}, // missing role-arn
		},
	}

	err := cfg.Build()
	assert.ErrorContains(t, err, "assume-role entry 0 is missing a required role-arn")
}

func cleanup() {
	viper.Reset()
}
