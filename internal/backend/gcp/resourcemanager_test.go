package gcp

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// fakeResourceManager is a hermetic stand-in for the resource-manager seam. It
// resolves project and folder parents from static maps and records the folder
// lookups performed so a test can assert the walk order.
type fakeResourceManager struct {
	projectParents map[string]string
	folderParents  map[string]string
	projectErr     error
	folderErr      error
	folderCalls    []string
}

func (f *fakeResourceManager) ProjectParent(_ context.Context, name string) (string, error) {
	if f.projectErr != nil {
		return "", f.projectErr
	}
	return f.projectParents[name], nil
}

func (f *fakeResourceManager) FolderParent(_ context.Context, name string) (string, error) {
	f.folderCalls = append(f.folderCalls, name)
	if f.folderErr != nil {
		return "", f.folderErr
	}
	return f.folderParents[name], nil
}

func TestResolveOrg(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		rm              *fakeResourceManager
		projectNumber   string
		want            string
		wantErr         bool
		wantFolderCalls []string
	}{
		{
			name: "project directly under organization",
			rm: &fakeResourceManager{
				projectParents: map[string]string{"projects/111": "organizations/12345"},
			},
			projectNumber: "111",
			want:          "12345",
		},
		{
			name: "project under one folder",
			rm: &fakeResourceManager{
				projectParents: map[string]string{"projects/111": "folders/100"},
				folderParents:  map[string]string{"folders/100": "organizations/999"},
			},
			projectNumber:   "111",
			want:            "999",
			wantFolderCalls: []string{"folders/100"},
		},
		{
			name: "project under nested folders",
			rm: &fakeResourceManager{
				projectParents: map[string]string{"projects/111": "folders/100"},
				folderParents: map[string]string{
					"folders/100": "folders/200",
					"folders/200": "organizations/42",
				},
			},
			projectNumber:   "111",
			want:            "42",
			wantFolderCalls: []string{"folders/100", "folders/200"},
		},
		{
			name: "unrecognized parent type errors",
			rm: &fakeResourceManager{
				projectParents: map[string]string{"projects/111": "billingAccounts/abc"},
			},
			projectNumber: "111",
			wantErr:       true,
		},
		{
			name: "project lookup error propagates",
			rm: &fakeResourceManager{
				projectErr: errors.New("permission denied"),
			},
			projectNumber: "111",
			wantErr:       true,
		},
		{
			name: "folder lookup error propagates",
			rm: &fakeResourceManager{
				projectParents: map[string]string{"projects/111": "folders/100"},
				folderErr:      errors.New("permission denied"),
			},
			projectNumber:   "111",
			wantErr:         true,
			wantFolderCalls: []string{"folders/100"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolveOrg(context.Background(), tt.rm, tt.projectNumber)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("resolveOrg(%q) = %q, want error", tt.projectNumber, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveOrg(%q) unexpected error: %v", tt.projectNumber, err)
			}
			if got != tt.want {
				t.Errorf("resolveOrg(%q) = %q, want %q", tt.projectNumber, got, tt.want)
			}
			if tt.wantFolderCalls != nil && !slices.Equal(tt.rm.folderCalls, tt.wantFolderCalls) {
				t.Errorf("folder walk = %v, want %v", tt.rm.folderCalls, tt.wantFolderCalls)
			}
		})
	}
}

func TestResolveOrgErrorMessages(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		rm         *fakeResourceManager
		wantErrHas []string
	}{
		{
			name: "project lookup error names the project and is package-prefixed",
			rm: &fakeResourceManager{
				projectErr: errors.New("permission denied"),
			},
			wantErrHas: []string{"gcp:", "111"},
		},
		{
			name: "folder lookup error names the failing folder and is package-prefixed",
			rm: &fakeResourceManager{
				projectParents: map[string]string{"projects/111": "folders/100"},
				folderErr:      errors.New("permission denied"),
			},
			wantErrHas: []string{"gcp:", "folders/100"},
		},
		{
			name: "unrecognized parent error is package-prefixed",
			rm: &fakeResourceManager{
				projectParents: map[string]string{"projects/111": "billingAccounts/abc"},
			},
			wantErrHas: []string{"gcp:", "billingAccounts/abc"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := resolveOrg(context.Background(), tt.rm, "111")
			if err == nil {
				t.Fatalf("resolveOrg(111) = nil error, want error")
			}
			for _, want := range tt.wantErrHas {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("resolveOrg error %q does not contain %q", err.Error(), want)
				}
			}
		})
	}
}
