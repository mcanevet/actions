package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tinkerbell/actions/enrollsecureboot/enroll"
)

// maxCertBytes bounds how much of the certificate response body is read, far
// more than any real X.509 certificate needs, so a misbehaving or malicious
// server can't exhaust memory.
const maxCertBytes = 1 << 20 // 1MiB

var httpClient = &http.Client{Timeout: 30 * time.Second}

// efivarfsPath is where efivarfs is expected to be mounted. The volumes
// Tinkerbell mounts into an action container are non-recursive bind mounts,
// so the host's efivarfs submount here isn't necessarily visible - see
// ensureEfivarfsMounted.
const efivarfsPath = "/sys/firmware/efi/efivars"

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	logger.Info("EnrollSecureBoot - Enroll a UEFI Secure Boot trust anchor")

	if err := run(logger); err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	dbCertURL := os.Getenv("DB_CERT_URL")
	if dbCertURL == "" {
		return errors.New("no certificate URL specified with environment variable [DB_CERT_URL]")
	}

	if err := ensureEfivarfsMounted(); err != nil {
		return fmt.Errorf("mounting efivarfs: %w", err)
	}

	dbCertPEM, err := fetchCert(dbCertURL)
	if err != nil {
		return fmt.Errorf("fetching db certificate from %s: %w", dbCertURL, err)
	}

	opts := enroll.Options{
		PreserveVendorCertificates:   parseBoolEnv("PRESERVE_VENDOR_CERTIFICATES"),
		IncludeWellKnownCertificates: parseBoolEnv("INCLUDE_WELL_KNOWN_CERTIFICATES"),
	}

	if err := enroll.Enroll(dbCertPEM, opts); err != nil {
		return fmt.Errorf("enrolling secure boot keys: %w", err)
	}

	logger.Info("Successfully enrolled Secure Boot keys", "dbCertURL", dbCertURL, "opts", opts)
	return nil
}

// parseBoolEnv reports whether the named environment variable is set to a
// true-ish value (per strconv.ParseBool). Unset or unparseable values are
// treated as false - both options default to the narrowest trust set.
func parseBoolEnv(name string) bool {
	v, err := strconv.ParseBool(os.Getenv(name))
	return err == nil && v
}

// ensureEfivarfsMounted mounts efivarfs at efivarfsPath if it isn't already,
// so this is safe to run whether or not the caller's volume mounts already
// expose the host's efivarfs.
func ensureEfivarfsMounted() error {
	mounted, err := isMounted(efivarfsPath)
	if err != nil {
		return err
	}
	if mounted {
		return nil
	}
	return syscall.Mount("efivarfs", efivarfsPath, "efivarfs", 0, "")
}

func isMounted(path string) (bool, error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		// mountinfo fields: id parent major:minor root <mountPoint> options ...
		fields := strings.Fields(line)
		if len(fields) > 4 && fields[4] == path {
			return true, nil
		}
	}
	return false, nil
}

func fetchCert(url string) ([]byte, error) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCertBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxCertBytes {
		return nil, fmt.Errorf("response body exceeds %d bytes", maxCertBytes)
	}

	return body, nil
}
