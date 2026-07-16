package pkg

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/ecs-inventory/internal/config"
	"github.com/anchore/ecs-inventory/pkg/logger"
)

type mockLogger struct{}

func (m *mockLogger) Error(msg string, err error, args ...interface{}) {}
func (m *mockLogger) Warn(msg string, args ...interface{})             {}
func (m *mockLogger) Warnf(msg string, args ...interface{})            {}
func (m *mockLogger) Info(msg string, args ...interface{})             {}
func (m *mockLogger) Debug(msg string, args ...interface{})            {}
func (m *mockLogger) Debugf(msg string, args ...interface{})           {}

func TestSetLogger(t *testing.T) {
	mock := &mockLogger{}
	SetLogger(mock)
	assert.Equal(t, logger.Logger(mock), log)
}

func TestBuildInventoryPasses(t *testing.T) {
	tests := []struct {
		name        string
		region      string
		assumeRoles []config.AssumeRoleConfig
		want        []inventoryPass
	}{
		{
			name:   "no roles uses top-level region",
			region: "us-east-1",
			want:   []inventoryPass{{region: "us-east-1"}},
		},
		{
			name:   "no roles and empty region still yields a single pass",
			region: "",
			want:   []inventoryPass{{region: ""}},
		},
		{
			name:   "single role uses its own region and ignores top-level region",
			region: "us-east-1",
			assumeRoles: []config.AssumeRoleConfig{
				{RoleARN: "arn:aws:iam::123456789012:role/foo", ExternalID: "ext", Region: "us-west-2"},
			},
			want: []inventoryPass{
				{region: "us-west-2", assumeRoleARN: "arn:aws:iam::123456789012:role/foo", externalID: "ext"},
			},
		},
		{
			name:   "multiple roles produce one pass each",
			region: "us-east-1",
			assumeRoles: []config.AssumeRoleConfig{
				{RoleARN: "arn:aws:iam::111111111111:role/a", Region: "us-west-2"},
				{RoleARN: "arn:aws:iam::222222222222:role/b", Region: "eu-west-1"},
			},
			want: []inventoryPass{
				{region: "us-west-2", assumeRoleARN: "arn:aws:iam::111111111111:role/a"},
				{region: "eu-west-1", assumeRoleARN: "arn:aws:iam::222222222222:role/b"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, buildInventoryPasses(tt.region, tt.assumeRoles))
		})
	}
}
