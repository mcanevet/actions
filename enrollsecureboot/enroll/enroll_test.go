package enroll

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/foxboron/go-uefi/efi/fs"
	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/spf13/afero"
)

const (
	efivarsDir = "/sys/firmware/efi/efivars"
	globalGUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
)

// useMemFS swaps go-uefi's backing filesystem for an in-memory one for the
// duration of the test, and restores the original afterwards.
func useMemFS(t *testing.T) afero.Fs {
	t.Helper()
	orig := fs.Fs
	mem := afero.NewMemMapFs()
	if err := mem.MkdirAll(efivarsDir, 0o755); err != nil {
		t.Fatalf("creating %s: %v", efivarsDir, err)
	}
	fs.SetFS(mem)
	t.Cleanup(func() { fs.SetFS(orig) })
	return mem
}

// setupModeAttrs is a non-zero attribute bitmask sufficient for SetupMode
// fixtures - GetSetupMode doesn't enforce a specific bitmask.
var setupModeAttrs = []byte{0x07, 0x00, 0x00, 0x00}

// writeEfivar writes a raw efivarfs entry: a 4-byte little-endian attributes
// header followed by value.
func writeEfivar(t *testing.T, memfs afero.Fs, name string, attrs, value []byte) {
	t.Helper()
	buf := append(append([]byte{}, attrs...), value...)
	if err := afero.WriteFile(memfs, efivarsDir+"/"+name, buf, 0o644); err != nil {
		t.Fatalf("writing fixture %s: %v", name, err)
	}
}

func setSetupMode(t *testing.T, memfs afero.Fs, enabled bool) {
	t.Helper()
	v := byte(0)
	if enabled {
		v = 1
	}
	writeEfivar(t, memfs, "SetupMode-"+globalGUID, setupModeAttrs, []byte{v})
}

// selfSignedCertPEM generates a throwaway self-signed certificate for use as
// the db payload under test, PEM-encoded like a real certificate download.
func selfSignedCertPEM(t *testing.T, commonName string) ([]byte, *x509.Certificate) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert
}

// readVarEntry reads back a variable written to efivarfs and returns the
// signature database it authenticates along with the unverified
// authentication wrapper, without checking the PKCS7 signature.
func readVarEntry(t *testing.T, memfs afero.Fs, name string) (signature.SignatureDatabase, *signature.EFIVariableAuthentication2) {
	t.Helper()

	raw, err := afero.ReadFile(memfs, efivarsDir+"/"+name)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}

	// Strip the 4-byte attributes header ParseEfivars would otherwise strip.
	buf := bytes.NewBuffer(raw[4:])

	auth, err := signature.ReadEFIVariableAuthencation2(buf)
	if err != nil {
		t.Fatalf("parsing auth header for %s: %v", name, err)
	}

	sigDB, err := signature.ReadSignatureDatabase(buf)
	if err != nil {
		t.Fatalf("parsing signature database for %s: %v", name, err)
	}

	return sigDB, auth
}

// readSignedVar reads back a variable written to efivarfs, asserts that its
// PKCS7 authentication wrapper verifies against signerCert - the throwaway
// identity Enroll signs every write with - and returns the signature
// database it authenticates.
func readSignedVar(t *testing.T, memfs afero.Fs, name string, signerCert *x509.Certificate) signature.SignatureDatabase {
	t.Helper()

	sigDB, auth := readVarEntry(t, memfs, name)

	ok, err := auth.Verify(signerCert)
	if err != nil {
		t.Fatalf("%s: verifying PKCS7 signature: %v", name, err)
	}
	if !ok {
		t.Fatalf("%s: PKCS7 signature did not verify against the throwaway signer certificate", name)
	}

	return sigDB
}

func certDER(t *testing.T, sigDB signature.SignatureDatabase) []byte {
	t.Helper()
	if len(sigDB) != 1 || len(sigDB[0].Signatures) != 1 {
		t.Fatalf("expected exactly one signature list with one entry, got %+v", sigDB)
	}
	return sigDB[0].Signatures[0].Data
}

func TestEnroll_NotInSetupMode(t *testing.T) {
	memfs := useMemFS(t)
	setSetupMode(t, memfs, false)

	dbCertPEM, _ := selfSignedCertPEM(t, "db")

	err := Enroll(dbCertPEM, Options{})
	if !errors.Is(err, ErrNotInSetupMode) {
		t.Fatalf("Enroll() error = %v, want %v", err, ErrNotInSetupMode)
	}
}

func TestEnroll_Success(t *testing.T) {
	memfs := useMemFS(t)
	setSetupMode(t, memfs, true)

	dbCertPEM, dbCert := selfSignedCertPEM(t, "db")

	if err := Enroll(dbCertPEM, Options{}); err != nil {
		t.Fatalf("Enroll() error = %v", err)
	}

	// KEK's payload is the throwaway signer's own identity certificate, so
	// read it once, unverified, to learn that identity, then use it below to
	// actually verify every variable's PKCS7 wrapper - including db, which
	// is signed by the same key but carries the caller-supplied certificate
	// as its payload instead.
	kekSigDB, _ := readVarEntry(t, memfs, "KEK-"+globalGUID)
	signerCert, err := x509.ParseCertificate(certDER(t, kekSigDB))
	if err != nil {
		t.Fatalf("parsing throwaway signer certificate: %v", err)
	}

	dbEntry := certDER(t, readSignedVar(t, memfs, "db-d719b2cb-3d3a-4596-a3bc-dad00e67656f", signerCert))
	if !bytes.Equal(dbEntry, dbCert.Raw) {
		t.Error("db entry does not match the supplied certificate")
	}

	kekEntry := certDER(t, readSignedVar(t, memfs, "KEK-"+globalGUID, signerCert))
	pkEntry := certDER(t, readSignedVar(t, memfs, "PK-"+globalGUID, signerCert))

	if !bytes.Equal(kekEntry, pkEntry) {
		t.Error("KEK and PK entries should both be the same throwaway identity certificate")
	}
	if bytes.Equal(kekEntry, dbEntry) {
		t.Error("KEK/PK entry should be the throwaway identity certificate, not the db certificate")
	}
}

func TestEnroll_InvalidDBCert(t *testing.T) {
	memfs := useMemFS(t)
	setSetupMode(t, memfs, true)

	if err := Enroll([]byte("not a certificate"), Options{}); err == nil {
		t.Fatal("Enroll() with invalid PEM data: expected an error, got nil")
	}
}

// dbEfivar is the well-known db efivarfs entry name used throughout these
// tests.
const dbEfivar = "db-d719b2cb-3d3a-4596-a3bc-dad00e67656f"

// dbAttrs is the attribute bitmask Getdb() requires db's efivarfs entry to
// have (NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS |
// TIME_BASED_AUTHENTICATED_WRITE_ACCESS = 0x27), matching what a real
// firmware sets on an authenticated Secure Boot variable.
var dbAttrs = []byte{0x27, 0x00, 0x00, 0x00}

// allCertDERs flattens every signature entry across every list in sigDB into
// a slice of raw certificate DER bytes.
func allCertDERs(sigDB signature.SignatureDatabase) [][]byte {
	var certs [][]byte
	for _, list := range sigDB {
		for _, sig := range list.Signatures {
			certs = append(certs, sig.Data)
		}
	}
	return certs
}

func containsCert(certs [][]byte, want []byte) bool {
	for _, c := range certs {
		if bytes.Equal(c, want) {
			return true
		}
	}
	return false
}

// vendorFixtureSigDB builds a serialized signature database containing a
// single throwaway "vendor" cert, in the plain (unauthenticated) form
// Getdb()/GetKEK() read back from efivarfs - i.e. what a real firmware
// exposes for an already-accepted variable.
func vendorFixtureSigDB(t *testing.T, commonName string) (*x509.Certificate, []byte) {
	t.Helper()
	_, cert := selfSignedCertPEM(t, commonName)
	sigDB := signature.NewSignatureDatabase()
	if err := appendCert(sigDB, cert); err != nil {
		t.Fatalf("building %s fixture sigDB: %v", commonName, err)
	}
	var buf bytes.Buffer
	signature.WriteSignatureDatabase(&buf, *sigDB)
	return cert, buf.Bytes()
}

func TestEnroll_PreserveVendorCertificates(t *testing.T) {
	memfs := useMemFS(t)
	setSetupMode(t, memfs, true)

	// Simulate vendor factory-default db/KEK already sitting in efivarfs, as
	// left behind by a ResetAllKeysToDefault BMC action run before Enroll -
	// DeletePK (which enters Setup Mode) only removes PK, so db/KEK still
	// hold whatever ResetAllKeysToDefault restored.
	vendorDBCert, vendorDBBytes := vendorFixtureSigDB(t, "vendor-oem-db")
	writeEfivar(t, memfs, dbEfivar, dbAttrs, vendorDBBytes)
	vendorKEKCert, vendorKEKBytes := vendorFixtureSigDB(t, "vendor-oem-kek")
	writeEfivar(t, memfs, "KEK-"+globalGUID, dbAttrs, vendorKEKBytes)

	dbCertPEM, dbCert := selfSignedCertPEM(t, "db")

	if err := Enroll(dbCertPEM, Options{PreserveVendorCertificates: true}); err != nil {
		t.Fatalf("Enroll() error = %v", err)
	}

	sigDB, _ := readVarEntry(t, memfs, dbEfivar)
	certs := allCertDERs(sigDB)

	if !containsCert(certs, vendorDBCert.Raw) {
		t.Error("vendor cert was not preserved in db")
	}
	if !containsCert(certs, dbCert.Raw) {
		t.Error("newly enrolled db cert is missing")
	}

	kekSigDB, _ := readVarEntry(t, memfs, "KEK-"+globalGUID)
	kekCerts := allCertDERs(kekSigDB)

	if !containsCert(kekCerts, vendorKEKCert.Raw) {
		t.Error("vendor cert was not preserved in KEK")
	}
	if len(kekCerts) != 2 {
		t.Errorf("expected vendor KEK cert + throwaway signer cert, got %d entries", len(kekCerts))
	}
}

func TestEnroll_PreserveVendorCertificates_NoExistingDB(t *testing.T) {
	memfs := useMemFS(t)
	setSetupMode(t, memfs, true)

	// No db efivarfs entry exists at all - Enroll must not fail just because
	// there's nothing to preserve.
	dbCertPEM, dbCert := selfSignedCertPEM(t, "db")

	if err := Enroll(dbCertPEM, Options{PreserveVendorCertificates: true}); err != nil {
		t.Fatalf("Enroll() error = %v", err)
	}

	sigDB, _ := readVarEntry(t, memfs, dbEfivar)
	if !containsCert(allCertDERs(sigDB), dbCert.Raw) {
		t.Error("newly enrolled db cert is missing")
	}
}

func TestEnroll_IncludeWellKnownCertificates(t *testing.T) {
	memfs := useMemFS(t)
	setSetupMode(t, memfs, true)

	dbCertPEM, dbCert := selfSignedCertPEM(t, "db")

	if err := Enroll(dbCertPEM, Options{IncludeWellKnownCertificates: true}); err != nil {
		t.Fatalf("Enroll() error = %v", err)
	}

	wellKnown, err := wellKnownDBCertificates()
	if err != nil {
		t.Fatalf("loading well-known db certificates: %v", err)
	}
	if len(wellKnown) == 0 {
		t.Fatal("no well-known db certificates embedded")
	}

	sigDB, _ := readVarEntry(t, memfs, dbEfivar)
	certs := allCertDERs(sigDB)

	for _, cert := range wellKnown {
		if !containsCert(certs, cert.Raw) {
			t.Errorf("well-known certificate %s missing from db", cert.Subject)
		}
	}
	if !containsCert(certs, dbCert.Raw) {
		t.Error("newly enrolled db cert is missing")
	}
}
