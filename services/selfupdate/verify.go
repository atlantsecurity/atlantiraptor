package selfupdate

import (
	"fmt"
	"os"
	"strings"

	"www.velocidex.com/golang/go-pe"
	"www.velocidex.com/golang/velociraptor/utils"
)

// SignerName is Atlant Security's legal entity name as it appears in
// the Authenticode certificate issued by Azure Artifact Signing.
const SignerName = "Atlant Security EOOD"

// Artifact Signing certificates are issued by Microsoft's identity
// verified code signing CAs ("Microsoft ID Verified CS AOC CA 03" and
// its siblings).
const (
	issuerOrg      = "Microsoft Corporation"
	issuerCNPrefix = "Microsoft ID Verified CS"
)

// parseDN splits a distinguished name like "C=BG, O=x, CN=y".
func parseDN(dn string) map[string]string {
	result := make(map[string]string)
	for _, part := range strings.Split(dn, ", ") {
		k, v, ok := strings.Cut(part, "=")
		if ok {
			result[strings.ToUpper(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	return result
}

// checkSignerNames checks the primary signature's signer and issuer.
func checkSignerNames(subject, issuer string) error {
	s := parseDN(subject)
	if s["CN"] != SignerName || s["O"] != SignerName {
		return fmt.Errorf("signed by %q, not %v", subject, SignerName)
	}
	i := parseDN(issuer)
	if i["O"] != issuerOrg || !strings.HasPrefix(i["CN"], issuerCNPrefix) {
		return fmt.Errorf("signing certificate issued by %q, not Microsoft's code signing CA", issuer)
	}
	return nil
}

// readSigner returns the subject and issuer of the primary
// Authenticode signer of a PE file. This only reads the names; the
// signature itself is checked by verifyTrust.
func readSigner(path string) (subject, issuer string, err error) {
	fd, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer fd.Close()

	st, err := fd.Stat()
	if err != nil {
		return "", "", err
	}
	pe_file, err := pe.NewPEFileWithSize(fd, st.Size())
	if err != nil {
		return "", "", fmt.Errorf("not a Windows executable: %w", err)
	}
	pkcs7_obj, err := pe.ParseAuthenticode(pe_file)
	if err != nil {
		return "", "", fmt.Errorf("not signed: %w", err)
	}
	signer := pe.PKCS7ToOrderedDict(pkcs7_obj)
	return utils.GetString(signer, "Signer.Subject"),
		utils.GetString(signer, "Signer.IssuerName"), nil
}

// VerifyBinary runs every check a downloaded binary must pass before
// it replaces the running one: an Authenticode signature that Windows
// trusts, from Atlant Security's certificate.
func VerifyBinary(path string) (string, error) {
	subject, issuer, err := readSigner(path)
	if err != nil {
		return "", err
	}
	err = checkSignerNames(subject, issuer)
	if err != nil {
		return subject, err
	}
	err = verifyTrust(path)
	if err != nil {
		return subject, fmt.Errorf("signature not trusted: %w", err)
	}
	return subject, nil
}
