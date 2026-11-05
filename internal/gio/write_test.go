package gio

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWriteFileCreates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "checksums.txt")

	require.NoError(t, WriteFile(path, []byte("hello\n"), 0o644))

	bts, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "hello\n", string(bts))

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), info.Mode())
	require.Empty(t, leftoverTempFiles(t, dir))
}

func TestWriteFileReplaces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "checksums.txt")

	require.NoError(t, os.WriteFile(path, []byte("old\n"), 0o600))

	require.NoError(t, WriteFile(path, []byte("new\n"), 0o644))

	bts, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "new\n", string(bts))

	// existing permissions are preserved.
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode())
	require.Empty(t, leftoverTempFiles(t, dir))
}

func TestWriteFileSameContentIsNoop(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "checksums.txt")
	data := []byte("same\n")

	require.NoError(t, WriteFile(path, data, 0o644))
	info, err := os.Stat(path)
	require.NoError(t, err)

	// make sure the mtime resolution is past.
	time.Sleep(10 * time.Millisecond)

	require.NoError(t, WriteFile(path, data, 0o644))
	info2, err := os.Stat(path)
	require.NoError(t, err)

	require.True(t, info2.ModTime().Equal(info.ModTime()))
	require.Empty(t, leftoverTempFiles(t, dir))
}

func TestWriteFileMissingDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing", "checksums.txt")

	err := WriteFile(path, []byte("data\n"), 0o644)
	require.Error(t, err)

	_, statErr := os.Stat(path)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestWriteFileFailureKeepsOriginal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "checksums.txt")
	original := []byte("original\n")
	require.NoError(t, os.WriteFile(path, original, 0o644))

	require.NoError(t, os.Chmod(dir, 0o555))
	t.Cleanup(func() {
		_ = os.Chmod(dir, 0o755)
	})

	err := WriteFile(path, []byte("new\n"), 0o644)
	require.Error(t, err)

	bts, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, original, bts)
}

func leftoverTempFiles(t *testing.T, dir string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, ".*.tmp-*"))
	require.NoError(t, err)
	return matches
}
