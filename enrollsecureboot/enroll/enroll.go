// Package enroll enrolls a UEFI Secure Boot trust anchor while the firmware
// is in Setup Mode.
package enroll

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"time"

	"github.com/foxboron/go-uefi/efi"
	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efi/util"
	"github.com/foxboron/go-uefi/efivar"
)

// ErrNotInSetupMode is returned when the firmware isn't in UEFI Setup Mode,
// the only state in which new Secure Boot keys can be written.
var ErrNotInSetupMode = errors.New("firmware is not in UEFI Setup Mode")

//go:embed certs/wellknown/*.der
var wellKnownDBCertsFS embed.FS

// Options controls which certificates, beyond dbCertPEM itself, get enrolled
// into db. Both default to false: the narrowest trust set (only dbCertPEM),
// matching Talos's own IncludeWellKnownCertificates default.
type Options struct {
	// PreserveVendorCertificates keeps whatever is already enrolled in db
	// (typically the vendor's factory-default set, restored by a
	// ResetAllKeysToDefault BMC action run before Enroll) instead of
	// discarding it. This is the actual, current, machine-specific trust
	// set - it can include vendor OEM certs no generic bundle would know
	// about - but it isn't reproducible across different hardware/firmware.
	PreserveVendorCertificates bool
	// IncludeWellKnownCertificates additionally enrolls a small, fixed
	// bundle of Microsoft's UEFI CA certificates (the same ones commonly
	// used to sign third-party Option ROM drivers), regardless of what's
	// currently in db. Deterministic and reproducible, but generic - it
	// won't include vendor-specific certs.
	IncludeWellKnownCertificates bool
}

// Enroll enrolls dbCertPEM, a PEM-encoded X.509 certificate, into the db
// signature database, trusting it to verify signed images at boot.
//
// KEK is deliberately not touched: KEK plays no role in boot-time image or
// driver verification (only db/dbx are), and leaving the vendor's factory
// KEK intact preserves Microsoft's KEK, i.e. the ability to later apply
// officially signed dbx revocation updates. PK is populated with a freshly
// generated, throwaway self-signed keypair: it is needed solely to exit
// Setup Mode (writing PK is what exits), and Setup Mode accepts any
// well-formed signed variable update regardless of whether the signing key
// is already trusted. Writing db first, PK last, matches the
// sd-boot/authoritative enrollment order.
//
// The firmware must already be in Setup Mode - reset its Secure Boot keys
// (for example via Redfish's ResetKeys action) before calling Enroll.
func Enroll(dbCertPEM []byte, opts Options) error {
	if !efi.GetSetupMode() {
		return ErrNotInSetupMode
	}

	dbCert, err := parseCertPEM(dbCertPEM)
	if err != nil {
		return fmt.Errorf("parsing db certificate: %w", err)
	}

	signerKey, signerCert, err := generateSelfSignedKey()
	if err != nil {
		return fmt.Errorf("generating throwaway signing key: %w", err)
	}

	dbSigDB, err := buildDBSignatureDatabase(dbCert, opts)
	if err != nil {
		return fmt.Errorf("building db signature database: %w", err)
	}

	if err := writeSigDB(efivar.Db, dbSigDB, signerKey, signerCert); err != nil {
		return fmt.Errorf("writing db: %w", err)
	}
	if err := writeVar(efivar.PK, signerCert, signerKey, signerCert); err != nil {
		return fmt.Errorf("writing PK: %w", err)
	}

	return nil
}

// buildDBSignatureDatabase assembles the full db content to write: the
// existing (vendor) db entries and/or the well-known Microsoft certs, per
// opts, followed by dbCert itself.
func buildDBSignatureDatabase(dbCert *x509.Certificate, opts Options) (*signature.SignatureDatabase, error) {
	sigDB := signature.NewSignatureDatabase()

	if opts.PreserveVendorCertificates {
		existing, err := readExisting(efi.Getdb)
		if err != nil {
			return nil, fmt.Errorf("reading existing db: %w", err)
		}
		if existing != nil {
			sigDB.AppendDatabase(existing)
		}
	}

	if opts.IncludeWellKnownCertificates {
		certs, err := wellKnownDBCertificates()
		if err != nil {
			return nil, fmt.Errorf("loading well-known db certificates: %w", err)
		}
		for _, cert := range certs {
			if err := appendCert(sigDB, cert); err != nil {
				return nil, err
			}
		}
	}

	if err := appendCert(sigDB, dbCert); err != nil {
		return nil, err
	}

	return sigDB, nil
}

// readExisting returns the current contents of a signature database (e.g.
// efi.Getdb), tolerating a not-yet-set variable as empty rather than an error.
func readExisting(get func() (*signature.SignatureDatabase, error)) (*signature.SignatureDatabase, error) {
	existing, err := get()
	if err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	return existing, nil
}

// wellKnownDBCertificates parses the embedded, vendored Microsoft UEFI CA
// certificates (the same well-known bundle Talos's own secureboot database
// generator embeds) into X.509 certificates.
func wellKnownDBCertificates() ([]*x509.Certificate, error) {
	entries, err := wellKnownDBCertsFS.ReadDir("certs/wellknown")
	if err != nil {
		return nil, err
	}

	certs := make([]*x509.Certificate, 0, len(entries))
	for _, entry := range entries {
		der, err := wellKnownDBCertsFS.ReadFile("certs/wellknown/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", entry.Name(), err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", entry.Name(), err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// appendCert appends a single-entry signature list containing cert to sigDB.
func appendCert(sigDB *signature.SignatureDatabase, cert *x509.Certificate) error {
	list := signature.NewSignatureList(signature.CERT_X509_GUID)
	if err := list.AppendBytes(util.EFIGUID{}, cert.Raw); err != nil {
		return err
	}
	sigDB.AppendList(list)
	return nil
}

func parseCertPEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("no PEM data found")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("expected a CERTIFICATE PEM block, got %q", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

// generateSelfSignedKey generates a throwaway RSA keypair and a self-signed
// certificate, used to authenticate the Secure Boot variable writes below.
func generateSelfSignedKey() (*rsa.PrivateKey, *x509.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tinkerbell-enrollsecureboot"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:         true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}

	return key, cert, nil
}

// writeVar builds a single-entry signature list containing cert, signs it as
// v (authenticated by signerKey/signerCert), and writes the result to
// efivarfs.
func writeVar(v efivar.Efivar, cert *x509.Certificate, signerKey *rsa.PrivateKey, signerCert *x509.Certificate) error {
	sigDB := signature.NewSignatureDatabase()
	if err := appendCert(sigDB, cert); err != nil {
		return err
	}
	return writeSigDB(v, sigDB, signerKey, signerCert)
}

// writeSigDB signs sigDB as v (authenticated by signerKey/signerCert) and
// writes the result to efivarfs.
func writeSigDB(v efivar.Efivar, sigDB *signature.SignatureDatabase, signerKey *rsa.PrivateKey, signerCert *x509.Certificate) error {
	_, marshalled, err := signature.SignEFIVariable(v, sigDB, signerKey, signerCert)
	if err != nil {
		return err
	}

	return efi.WriteEFIVariable(v.Name, marshalled.Bytes())
}
