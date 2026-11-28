// Package consolehttps serves the web console on a hostname of the
// customer's choice (normally on port 443) with a certificate that
// browsers trust: either one the administrator uploads or one issued
// automatically by Let's Encrypt.
//
// The extra listener runs next to the console address from the config
// file, which is never changed, so a bad setting can't lock anyone out:
// the original address keeps working. New settings are applied at once
// but stay "pending" until an administrator confirms them; unconfirmed
// settings roll back by themselves after a few minutes, and on restart.
package consolehttps

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const (
	ModeCertificate = "certificate"
	ModeLetsEncrypt = "letsencrypt"
)

// Settings is what an administrator configures. The private key is
// never part of it: it is stored encrypted next to it and never leaves
// the server.
type Settings struct {
	Enabled      bool   `json:"enabled"`
	Hostname     string `json:"hostname"`
	BindAddress  string `json:"bind_address,omitempty"`
	Port         uint32 `json:"port"`
	Mode         string `json:"mode"`
	RedirectHTTP bool   `json:"redirect_http"`
	Email        string `json:"email,omitempty"`

	// The certificate chain (PEM) in certificate mode.
	CertPEM string `json:"cert_pem,omitempty"`

	Updated   int64  `json:"updated,omitempty"`
	UpdatedBy string `json:"updated_by,omitempty"`
}

// Upload is a certificate as the administrator sends it: PEM
// certificate and key, or a PKCS#12 (.pfx/.p12) bundle.
type Upload struct {
	CertPEM     string `json:"cert_pem"`
	KeyPEM      string `json:"key_pem"`
	PFXBase64   string `json:"pfx_base64"`
	PFXPassword string `json:"pfx_password"`
}

func (u Upload) Empty() bool {
	return strings.TrimSpace(u.CertPEM) == "" && strings.TrimSpace(u.KeyPEM) == "" &&
		strings.TrimSpace(u.PFXBase64) == ""
}

// CertInfo describes a certificate for the console page.
type CertInfo struct {
	Subject   string   `json:"subject"`
	Issuer    string   `json:"issuer"`
	Names     []string `json:"names"`
	NotBefore int64    `json:"not_before"`
	NotAfter  int64    `json:"not_after"`
	// Trusted: the chain verifies against this server's system roots,
	// which is a good proxy for what browsers will do.
	Trusted      bool   `json:"trusted"`
	TrustError   string `json:"trust_error,omitempty"`
	SelfSigned   bool   `json:"self_signed,omitempty"`
	Fingerprint  string `json:"fingerprint_sha256,omitempty"`
	ChainLength  int    `json:"chain_length"`
	KeyAlgorithm string `json:"key_algorithm"`
}

// Ports the console must not take over. Filled from the config file.
type ReservedPort struct {
	Port uint32
	Use  string
}

var hostnameRe = regexp.MustCompile(`^(?i)(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$`)

// NormalizeHostname lowercases and trims a host name and rejects
// anything that is not a DNS name (or, in certificate mode, an IP).
func NormalizeHostname(h string, allowIP bool) (string, error) {
	h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
	h = strings.TrimPrefix(strings.TrimPrefix(h, "https://"), "http://")
	if i := strings.IndexAny(h, "/:"); i >= 0 && net.ParseIP(h) == nil {
		return "", errors.New("Enter only the host name, for example console.example.com, without https:// or a port.")
	}
	if h == "" {
		return "", errors.New("Enter the host name the console should answer on, for example console.example.com.")
	}
	if net.ParseIP(h) != nil {
		if !allowIP {
			return "", errors.New("Let's Encrypt needs a host name, not an IP address.")
		}
		return h, nil
	}
	if strings.HasPrefix(h, "*.") {
		return "", errors.New("Enter the exact host name, not a wildcard. A wildcard certificate is fine.")
	}
	if len(h) > 253 || !hostnameRe.MatchString(h) {
		return "", fmt.Errorf("%q is not a valid host name.", h)
	}
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return "", errors.New("Browsers can't get a trusted certificate for localhost. Use the server's real host name.")
	}
	return h, nil
}

// ValidateSettings checks everything except the certificate itself.
func ValidateSettings(s Settings, reserved []ReservedPort) (Settings, []string, error) {
	var warnings []string
	s.Mode = strings.ToLower(strings.TrimSpace(s.Mode))
	if s.Mode != ModeCertificate && s.Mode != ModeLetsEncrypt {
		return s, nil, errors.New("Choose how to get the certificate: upload one, or use Let's Encrypt.")
	}
	host, err := NormalizeHostname(s.Hostname, s.Mode == ModeCertificate)
	if err != nil {
		return s, nil, err
	}
	s.Hostname = host

	s.BindAddress = strings.TrimSpace(s.BindAddress)
	if s.BindAddress != "" && net.ParseIP(s.BindAddress) == nil {
		return s, nil, errors.New("The listen address must be an IP address of this server, or empty for all addresses.")
	}
	if s.Port == 0 {
		s.Port = 443
	}
	if s.Port > 65535 {
		return s, nil, errors.New("The port must be between 1 and 65535.")
	}
	for _, r := range reserved {
		if r.Port != 0 && r.Port == s.Port {
			return s, nil, fmt.Errorf("Port %d is already used by %s. Pick another port, normally 443.", s.Port, r.Use)
		}
		if s.RedirectHTTP && r.Port == 80 {
			return s, nil, fmt.Errorf("Port 80 is already used by %s, so http:// can't be redirected from it.", r.Use)
		}
	}
	if s.RedirectHTTP && s.Port == 80 {
		return s, nil, errors.New("The console can't serve HTTPS on port 80 and redirect port 80 at the same time.")
	}

	s.Email = strings.TrimSpace(s.Email)
	if s.Email != "" && (!strings.Contains(s.Email, "@") || strings.ContainsAny(s.Email, " \t\r\n<>")) {
		return s, nil, errors.New("The Let's Encrypt contact email doesn't look like an email address.")
	}
	if s.Mode == ModeLetsEncrypt {
		s.CertPEM = ""
		if s.Port != 443 && !s.RedirectHTTP {
			warnings = append(warnings, fmt.Sprintf(
				"Let's Encrypt checks the host name on port 443 (or port 80 with the http:// redirect on). "+
					"With the console on port %d, make sure port 443 or 80 of %s reaches this listener, or issuance fails.",
				s.Port, s.Hostname))
		}
	} else {
		s.Email = ""
	}
	s.Enabled = true
	return s, warnings, nil
}

// ParseUpload turns an upload into a PEM chain and a PEM private key and
// checks that they belong together.
func ParseUpload(u Upload) (certPEM string, keyPEM []byte, err error) {
	if strings.TrimSpace(u.PFXBase64) != "" {
		data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(u.PFXBase64))
		if err != nil {
			return "", nil, errors.New("The .pfx file could not be read.")
		}
		key, leaf, cas, err := pkcs12.DecodeChain(data, u.PFXPassword)
		if err != nil {
			if errors.Is(err, pkcs12.ErrIncorrectPassword) {
				return "", nil, errors.New("The .pfx password is wrong.")
			}
			return "", nil, fmt.Errorf("The .pfx file could not be opened: %v", err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return "", nil, fmt.Errorf("The private key in the .pfx file is not supported: %v", err)
		}
		var b strings.Builder
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
		for _, c := range cas {
			_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
		}
		certPEM = b.String()
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	} else {
		certPEM = strings.TrimSpace(u.CertPEM) + "\n"
		keyPEM = []byte(strings.TrimSpace(u.KeyPEM) + "\n")
		if strings.TrimSpace(u.CertPEM) == "" {
			return "", nil, errors.New("Paste or upload the certificate (PEM), or upload a .pfx file.")
		}
		if strings.TrimSpace(u.KeyPEM) == "" {
			return "", nil, errors.New("Paste or upload the private key that belongs to the certificate.")
		}
		if strings.Contains(string(keyPEM), "ENCRYPTED") {
			return "", nil, errors.New("The private key is password protected. Upload it without a password, or upload a .pfx file with its password.")
		}
	}
	if _, err := tls.X509KeyPair([]byte(certPEM), keyPEM); err != nil {
		return "", nil, fmt.Errorf("The certificate and private key don't belong together or could not be read: %v", err)
	}
	return certPEM, keyPEM, nil
}

// ParseChain returns the certificates in a PEM chain, leaf first.
func ParseChain(certPEM string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := []byte(certPEM)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("no certificate found")
	}
	return out, nil
}

// Roots used to judge whether browsers will trust a certificate. A
// variable so tests can supply their own.
var trustRoots = func() (*x509.CertPool, error) { return x509.SystemCertPool() }

// Now is the clock (tests replace it).
var Now = time.Now

// Describe reports on a chain without judging it.
func Describe(chain []*x509.Certificate, host string) CertInfo {
	leaf := chain[0]
	info := CertInfo{
		Subject:      leaf.Subject.CommonName,
		Issuer:       leaf.Issuer.CommonName,
		Names:        append([]string{}, leaf.DNSNames...),
		NotBefore:    leaf.NotBefore.Unix(),
		NotAfter:     leaf.NotAfter.Unix(),
		ChainLength:  len(chain),
		SelfSigned:   leaf.Issuer.String() == leaf.Subject.String(),
		KeyAlgorithm: keyAlgorithm(leaf),
	}
	if info.Subject == "" {
		info.Subject = leaf.Subject.String()
	}
	if info.Issuer == "" {
		info.Issuer = leaf.Issuer.String()
	}
	for _, ip := range leaf.IPAddresses {
		info.Names = append(info.Names, ip.String())
	}
	info.Fingerprint = fingerprint(leaf.Raw)

	roots, err := trustRoots()
	if err != nil || roots == nil {
		info.TrustError = "This server can't read its trusted root list to check the certificate."
		return info
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		DNSName:       host,
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		info.TrustError = trustProblem(err, info.SelfSigned)
	} else {
		info.Trusted = true
	}
	return info
}

func trustProblem(err error, selfSigned bool) string {
	var ua x509.UnknownAuthorityError
	switch {
	case selfSigned:
		return "This certificate is self-signed, so browsers will warn about it."
	case errors.As(err, &ua):
		return "Browsers won't recognise who issued this certificate. If it comes from a public authority, include the intermediate certificates (the full chain); if it comes from your company's own authority, only devices that trust it will accept it."
	}
	return "Browsers won't trust this certificate: " + err.Error()
}

// CheckCertificate validates a chain for use on host. Hard problems are
// errors; a certificate browsers may not trust only warns, and needs
// the administrator's confirmation.
func CheckCertificate(certPEM, host string) (CertInfo, []string, error) {
	chain, err := ParseChain(certPEM)
	if err != nil {
		return CertInfo{}, nil, fmt.Errorf("The certificate could not be read: %v", err)
	}
	leaf := chain[0]
	info := Describe(chain, host)
	now := Now()
	if now.After(leaf.NotAfter) {
		return info, nil, fmt.Errorf("This certificate expired on %s.", leaf.NotAfter.Format("2 January 2006"))
	}
	if now.Before(leaf.NotBefore) {
		return info, nil, fmt.Errorf("This certificate is not valid until %s.", leaf.NotBefore.Format("2 January 2006 15:04 MST"))
	}
	if err := leaf.VerifyHostname(host); err != nil {
		return info, nil, fmt.Errorf("This certificate is for %s, not %s.", strings.Join(info.Names, ", "), host)
	}
	if k, ok := leaf.PublicKey.(*rsa.PublicKey); ok && k.N.BitLen() < 2048 {
		return info, nil, errors.New("The certificate's RSA key is shorter than 2048 bits; browsers reject it.")
	}
	var warnings []string
	if !info.Trusted {
		warnings = append(warnings, info.TrustError)
	}
	if left := leaf.NotAfter.Sub(now); left < 30*24*time.Hour {
		warnings = append(warnings, fmt.Sprintf("This certificate expires in %d days (%s). Plan to replace it.",
			int(left.Hours()/24), leaf.NotAfter.Format("2 January 2006")))
	}
	return info, warnings, nil
}

func keyAlgorithm(c *x509.Certificate) string {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return c.PublicKeyAlgorithm.String()
}
