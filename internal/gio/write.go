package gio

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
)

// WriteFile atomically writes data to the named file with the given
// permissions.
//
// The data is first written to a temporary file in the same directory,
// synced and then renamed into place, so an error while writing never
// leaves a truncated file behind.
// If the file already exists, its permissions are preserved and, when
// its contents are already equal to data, it is left untouched.
func WriteFile(path string, data []byte, perm os.FileMode) error {
	mode := perm
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode()
		if current, err := os.ReadFile(path); err == nil && bytes.Equal(current, data) {
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}

	tmpName := tmp.Name()
	removeTmp := true
	defer func() {
		if removeTmp {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}

	removeTmp = false
	return nil
}
