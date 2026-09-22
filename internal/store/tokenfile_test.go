package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// fakeTempFile is a tokenTempFile whose each step can be made to fail.
type fakeTempFile struct {
	name     string
	chmodErr error
	writeErr error
	closeErr error
	closed   bool
	written  string
}

func (f *fakeTempFile) Name() string { return f.name }

func (f *fakeTempFile) Chmod(os.FileMode) error { return f.chmodErr }

func (f *fakeTempFile) WriteString(s string) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	f.written = s
	return len(s), nil
}

func (f *fakeTempFile) Close() error {
	f.closed = true
	return f.closeErr
}

// withTokenOps swaps the token-file seams for the duration of fn, restoring them
// immediately after (and on cleanup, in case fn panics).
func withTokenOps(t *testing.T, mkdir func(string, os.FileMode) error,
	create func(string, string) (tokenTempFile, error),
	rm func(string) error, rename func(string, string) error, fn func()) {
	t.Helper()
	oldMkdir, oldCreate, oldRemove, oldRename := osMkdirAll, osCreateTemp, osRemoveToken, osRenameToken
	osMkdirAll, osCreateTemp, osRemoveToken, osRenameToken = mkdir, create, rm, rename
	t.Cleanup(func() {
		osMkdirAll, osCreateTemp, osRemoveToken, osRenameToken = oldMkdir, oldCreate, oldRemove, oldRename
	})
	fn()
	osMkdirAll, osCreateTemp, osRemoveToken, osRenameToken = oldMkdir, oldCreate, oldRemove, oldRename
}

// osCreateTempReal is the unmodified create-temp seam used by a test that wants
// the real os.CreateTemp to run (and fail) against a missing directory.
var osCreateTempReal = osCreateTemp

// okSeams returns all-success seams; mkdir is a no-op so the synthetic paths
// never touch the real filesystem.
func okSeams() (func(string, os.FileMode) error, func(string, string) (tokenTempFile, error), func(string) error, func(string, string) error) {
	return func(string, os.FileMode) error { return nil },
		func(dir, pattern string) (tokenTempFile, error) {
			return &fakeTempFile{name: filepath.Join(dir, "tmp")}, nil
		},
		func(string) error { return nil },
		func(string, string) error { return nil }
}

func TestWriteTokenFileMkdirFailure(t *testing.T) {
	_, create, rm, rename := okSeams()
	mkdir := func(string, os.FileMode) error { return errors.New("mkdir denied") }
	withTokenOps(t, mkdir, create, rm, rename, func() {
		if err := WriteTokenFile("/a/b/token", "t"); err == nil {
			t.Fatal("mkdir failure swallowed")
		}
	})
}

func TestWriteTokenFileCreateTempFailure(t *testing.T) {
	mkdir, _, rm, rename := okSeams()
	create := func(string, string) (tokenTempFile, error) { return nil, errors.New("temp denied") }
	withTokenOps(t, mkdir, create, rm, rename, func() {
		if err := WriteTokenFile("/a/b/token", "t"); err == nil {
			t.Fatal("create-temp failure swallowed")
		}
	})
}

func TestWriteTokenFileChmodFailure(t *testing.T) {
	mkdir, _, rm, rename := okSeams()
	create := func(dir, _ string) (tokenTempFile, error) {
		return &fakeTempFile{name: filepath.Join(dir, "tmp"), chmodErr: errors.New("chmod denied")}, nil
	}
	withTokenOps(t, mkdir, create, rm, rename, func() {
		if err := WriteTokenFile("/a/b/token", "t"); err == nil {
			t.Fatal("chmod failure swallowed")
		}
	})
}

func TestWriteTokenFileWriteFailure(t *testing.T) {
	mkdir, _, rm, rename := okSeams()
	f := &fakeTempFile{name: "/a/b/tmp", writeErr: errors.New("write denied")}
	create := func(string, string) (tokenTempFile, error) { return f, nil }
	withTokenOps(t, mkdir, create, rm, rename, func() {
		if err := WriteTokenFile("/a/b/token", "t"); err == nil {
			t.Fatal("write failure swallowed")
		}
		if !f.closed {
			t.Error("temp file not closed on a write failure")
		}
	})
}

func TestWriteTokenFileCloseFailure(t *testing.T) {
	mkdir, _, rm, rename := okSeams()
	f := &fakeTempFile{name: "/a/b/tmp", closeErr: errors.New("close denied")}
	create := func(string, string) (tokenTempFile, error) { return f, nil }
	withTokenOps(t, mkdir, create, rm, rename, func() {
		if err := WriteTokenFile("/a/b/token", "t"); err == nil {
			t.Fatal("close failure swallowed")
		}
	})
}

func TestWriteTokenFileRenameFailure(t *testing.T) {
	mkdir, create, rm, _ := okSeams()
	rename := func(string, string) error { return errors.New("rename denied") }
	withTokenOps(t, mkdir, create, rm, rename, func() {
		if err := WriteTokenFile("/a/b/token", "t"); err == nil {
			t.Fatal("rename failure swallowed")
		}
	})
}

// TestWriteTokenFileSuccessUsesSeams proves the happy path calls each seam and
// writes exactly "token\n".
func TestWriteTokenFileSuccessUsesSeams(t *testing.T) {
	mkdir, _, rm, rename := okSeams()
	f := &fakeTempFile{name: "/a/b/tmp"}
	create := func(string, string) (tokenTempFile, error) { return f, nil }
	withTokenOps(t, mkdir, create, rm, rename, func() {
		if err := WriteTokenFile("/a/b/token", "my-token"); err != nil {
			t.Fatalf("WriteTokenFile: %v", err)
		}
		if f.written != "my-token\n" {
			t.Errorf("written = %q, want %q", f.written, "my-token\n")
		}
		if !f.closed {
			t.Error("temp file not closed")
		}
	})
}

// TestSeamRestoresAfterUse guards the restore so later tests use the real os.
func TestSeamRestoresAfterUse(t *testing.T) {
	dir := t.TempDir()
	withTokenOps(t, func(string, os.FileMode) error { return errors.New("x") },
		nil, nil, nil, func() {
			_ = WriteTokenFile(filepath.Join(dir, "t"), "t")
		})
	if err := WriteTokenFile(filepath.Join(dir, "real"), "real-token"); err != nil {
		t.Fatalf("seams not restored: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "real")); err != nil {
		t.Fatalf("real write failed: %v", err)
	}
}

// TestWriteTokenFileCreateTempRealError covers the default osCreateTemp closure's
// error branch: the directory does not exist and MkdirAll is a no-op seam, so
// os.CreateTemp fails for real.
func TestWriteTokenFileCreateTempRealError(t *testing.T) {
	withTokenOps(t,
		func(string, os.FileMode) error { return nil }, // skip mkdir
		osCreateTempReal, // real create-temp against a missing dir
		osRemoveToken, osRenameToken,
		func() {
			if err := WriteTokenFile("/nonexistent-dir-xyz/token", "t"); err == nil {
				t.Fatal("WriteTokenFile succeeded with a missing directory")
			}
		})
}
