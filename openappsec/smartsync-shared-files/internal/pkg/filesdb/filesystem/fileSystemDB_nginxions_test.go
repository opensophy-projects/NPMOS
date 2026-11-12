// NginxionS: a path of the REST API stays inside the root of the storage (CodeQL go/path-injection)
package filesystem

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPathsStayInTheRoot(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "storage") + "/"
	if err := os.MkdirAll(root, 0750); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(base, "secret")
	if err := os.WriteFile(secret, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	a := &Adapter{root: root, ttl: time.Minute}
	ctx := context.Background()

	if err := a.PutFile(ctx, "tenant/asset/file", []byte("ok"), false); err != nil {
		t.Fatalf("put inside the root: %v", err)
	}
	if data, err := a.GetFile(ctx, "tenant/asset/file"); err != nil || string(data) != "ok" {
		t.Fatalf("get inside the root: %q %v", data, err)
	}
	info, err := os.Stat(filepath.Join(root, "tenant/asset/file"))
	if err != nil || info.Mode().Perm()&0o007 != 0 {
		t.Fatalf("the file is readable by every user: %v %v", info.Mode(), err)
	}
	for _, p := range []string{"../secret", "tenant/../../secret", "/../secret", "../storage-other/x"} {
		if _, err := a.GetFile(ctx, p); err == nil {
			t.Errorf("GetFile(%q) read outside the root", p)
		}
		if err := a.PutFile(ctx, p, []byte("x"), false); err == nil {
			t.Errorf("PutFile(%q) wrote outside the root", p)
		}
		if _, err := a.GetFilesList(ctx, p); err == nil {
			t.Errorf("GetFilesList(%q) listed outside the root", p)
		}
	}
	if data, _ := os.ReadFile(secret); string(data) != "secret" {
		t.Fatal("the file outside the root was changed")
	}
}
