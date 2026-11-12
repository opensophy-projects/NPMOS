package policy

import (
	"context"
	"reflect"
	"testing"

	"openappsec.io/smartsync-tuning/models"
)

// NginxionS: the fixtures are the policy of the agent (JSON) the adapter reads, not local_policy.yaml; the version
// is the time of reading
var defaultSources = models.TrustedSourcesPolicy{NumOfSources: 3, SourcesIdentifiers: []models.Identifier{}}

func TestAdapter_GetPolicy(t *testing.T) {
	type args struct {
		ctx           context.Context
		tenantID      string
		path          string
		policyVersion int64
	}
	tests := []struct {
		name    string
		args    args
		path    string
		want    []models.AssetDetails
		wantErr bool
	}{
		{
			name:    "not found failure",
			args:    args{},
			path:    "testdata/not-exists.json",
			want:    []models.AssetDetails{},
			wantErr: true,
		},
		{
			name: "default policy",
			args: args{},
			path: "./testdata/policy.json",
			want: []models.AssetDetails{{AssetID: "Any", PolicyVersion: 0, Mode: "Detect", Level: "Critical",
				ApplicationUrls: "*", Type: models.WaapTypeWebApp, TrustedSources: defaultSources}},
			wantErr: false,
		},
		{
			name: "policy with specific rule",
			args: args{},
			path: "./testdata/policy_with_rule.json",
			want: []models.AssetDetails{{AssetID: "Any", PolicyVersion: 0, Mode: "Detect", Level: "Critical",
				ApplicationUrls: "*", Type: models.WaapTypeWebApp, TrustedSources: defaultSources},
				{
					Type:            models.WaapTypeWebApp,
					AssetID:         "example.com",
					Name:            "example.com",
					PolicyVersion:   0,
					Mode:            "Detect",
					Level:           "Critical",
					ApplicationUrls: "example.com",
					TrustedSources: models.TrustedSourcesPolicy{
						NumOfSources:       3,
						SourcesIdentifiers: []models.Identifier{{Value: "source-identifier-1"}, {Value: "source-identifier-2"}},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ad := Adapter{policyPath: tt.path}
			got, err := ad.GetPolicy(context.Background(), tt.args.tenantID, tt.args.path, tt.args.policyVersion)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPolicy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				got[i].PolicyVersion = 0 // the time the policy was read
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetPolicy() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAdapter_GetPolicyDetails(t *testing.T) {
	type args struct {
		ctx           context.Context
		tenantID      string
		assetID       string
		policyVersion int64
	}
	tests := []struct {
		name    string
		args    args
		path    string
		want    models.AssetDetails
		wantErr bool
	}{
		{
			name:    "not found failure",
			args:    args{assetID: "example.com"},
			path:    "./testdata/policy.json",
			want:    models.AssetDetails{},
			wantErr: true,
		},
		{
			name: "default policy",
			args: args{assetID: "Any"},
			path: "./testdata/policy.json",
			want: models.AssetDetails{AssetID: "Any", PolicyVersion: 0, Mode: "Detect", Level: "Critical",
				ApplicationUrls: "*", Type: models.WaapTypeWebApp, TrustedSources: defaultSources},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ad := Adapter{policyPath: tt.path}
			got, err := ad.GetPolicyDetails(context.Background(), tt.args.tenantID, tt.args.assetID,
				tt.args.policyVersion)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPolicyDetails() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			got.PolicyVersion = 0 // the time the policy was read
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetPolicyDetails() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAdapter_GetPolicyVersion(t *testing.T) {
	type args struct {
		ctx      context.Context
		tenantID string
		userID   string
	}
	tests := []struct {
		name    string
		args    args
		want    int
		wantErr bool
	}{
		{
			name: "not active return 0",
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := Adapter{}
			got, err := a.GetPolicyVersion(tt.args.ctx, tt.args.tenantID, tt.args.userID)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPolicyVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetPolicyVersion() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAdapter_GetTrustedSourcesPolicy(t *testing.T) {
	type args struct {
		ctx          context.Context
		tenantID     string
		assetID      string
		resourceName string
	}
	tests := []struct {
		name    string
		args    args
		want    models.TrustedSourcesPolicy
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := Adapter{}
			got, err := a.GetTrustedSourcesPolicy(tt.args.ctx, tt.args.tenantID, tt.args.assetID, tt.args.resourceName)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetTrustedSourcesPolicy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetTrustedSourcesPolicy() got = %v, want %v", got, tt.want)
			}
		})
	}
}

type conf struct {
}

func (c *conf) GetString(key string) (string, error) {
	return "./testdata/policy.json", nil
}

func TestNewAdapter(t *testing.T) {
	tests := []struct {
		name string
		want *Adapter
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &conf{}
			if got, _ := NewAdapter(c); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewAdapter() = %v, want %v", got, tt.want)
			}
		})
	}
}
