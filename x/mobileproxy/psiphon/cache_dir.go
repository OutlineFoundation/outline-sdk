//go:build psiphon

package psiphon

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

func getAndroidPackageName() (string, error) {
	f, err := os.Open("/proc/self/cmdline")
	if err != nil {
		return "", err
	}
	defer f.Close()

	// /proc/self/cmdline is NULL-terminated; read up to the first NULL.
	r := bufio.NewReader(f)
	line, err := r.ReadString('\x00')
	if err != nil && !errors.Is(err, bufio.ErrBufferFull) {
		// On success the NULL will be included; trim regardless.
	}
	pkg := strings.Trim(line, "\x00\r\n\t ")
	if pkg == "" {
		return "", errors.New("could not determine package name from /proc/self/cmdline")
	}
	return pkg, nil
}

// On Android, each app has a private data directory /data/user/<user-id>/<package>/ (something like /data/user/0/com.example.app/)
// Older devices, before multi user, used /data/data/<packageName>/. For backwards-compatibility, the OS still maintains symlinks so /data/data/... resolves to /data/user/<user-id>/ for the current user.
// This uses the directory /data/data/<packageName>/cache/
// It validates the directory exists (or creates it).
func androidPrivateCacheDir() (string, error) {
	pkg, err := getAndroidPackageName()
	if err != nil {
		return "", err
	}

	// Prefer legacy symlink location; it resolves to /data/user/<id>/<pkg>.
	p := filepath.Join("/data/data", pkg, "cache")

	// Ensure it exists (normally already does).
	if st, err := os.Stat(p); err == nil && st.IsDir() {
		return p, nil
	}
	if err := os.MkdirAll(p, 0700); err != nil {
		return "", err
	}
	return p, nil
}

func getUserCacheDir() (string, error) {
	var err error
	var cacheBaseDir string
	if runtime.GOOS == "android" {
		cacheBaseDir, err = androidPrivateCacheDir()
	} else {
		// For every other system os.UserCacheDir works okay
		cacheBaseDir, err = os.UserCacheDir()
	}
	if err != nil {
		return "", fmt.Errorf("failed to get the user cache directory: %w", err)
	}

	userCacheDir := path.Join(cacheBaseDir, "psiphon")
	if err := os.MkdirAll(userCacheDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create storage directory: %w", err)
	}

	return userCacheDir, nil
}
