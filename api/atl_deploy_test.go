package api

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Velocidex/yaml/v2"
	"www.velocidex.com/golang/velociraptor/config"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/utils/intunewin"
)

func deployTestConfig(urls ...string) *config_proto.Config {
	c := config.GetDefaultConfig()
	c.Client.ServerUrls = urls
	c.Client.CaCertificate = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	c.Client.Nonce = "test-nonce"
	c.Frontend.PrivateKey = "-----BEGIN RSA PRIVATE KEY-----\nSECRET\n-----END RSA PRIVATE KEY-----\n"
	c.OrgId = "O123"
	c.OrgName = "Acme #> Corp\n"
	return c
}

func TestDeployBundle(t *testing.T) {
	org := deployTestConfig("https://atl.example.com:8000/")
	b, err := newDeployBundle(org, time.Unix(1764320000, 0))
	if err != nil {
		t.Fatal(err)
	}

	// The org's own config is not changed.
	if org.Client.WritebackWindows == b.info.ClientConfig || org.Client.WindowsInstaller.ServiceName == "Atlantiraptor" {
		t.Fatal("org config was modified")
	}

	// The client config is the org's, with the MSI's Windows paths,
	// and never the server's private keys.
	if strings.Contains(b.info.ClientConfig, "SECRET") || strings.Contains(b.info.ClientConfig, "Frontend") {
		t.Fatalf("client config leaks server settings:\n%s", b.info.ClientConfig)
	}
	parsed := &config_proto.Config{}
	if err := yaml.Unmarshal([]byte(b.info.ClientConfig), parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Client.Nonce != "test-nonce" || parsed.Client.ServerUrls[0] != "https://atl.example.com:8000/" ||
		parsed.Client.WritebackWindows != `$ProgramFiles\Atlant Security\Atlantiraptor\atlantiraptor.writeback.yaml` ||
		parsed.Client.TempdirWindows != `$ProgramFiles\Atlant Security\Atlantiraptor\Tools` ||
		parsed.Client.WindowsInstaller.ServiceName != "Atlantiraptor" {
		t.Fatalf("unexpected client config: %v", parsed.Client)
	}
	if b.info.LocalOnly {
		t.Fatal("public URL reported as local only")
	}
	if !strings.HasPrefix(b.info.DownloadURL, "https://github.com/atlantsecurity/atlantiraptor/releases/") {
		t.Fatalf("download URL %v", b.info.DownloadURL)
	}

	config_b64 := base64.StdEncoding.EncodeToString([]byte(b.info.ClientConfig))
	leftover := regexp.MustCompile(`\{\{|\}\}`)
	for _, name := range b.info.Files {
		data, err := b.render(name)
		if err != nil {
			t.Fatalf("%v: %v", name, err)
		}
		if name == deployIntuneFile || name == deployConfigFile {
			continue
		}
		text := string(data)
		if leftover.MatchString(text) {
			t.Fatalf("%v has unexpanded template fields", name)
		}
		if name != deployDetectFile && !strings.Contains(text, config_b64) {
			t.Fatalf("%v does not carry the client config", name)
		}
		if name != deployDetectFile && (strings.Contains(text, "Acme #> Corp\n") || !strings.Contains(text, "Acme # > Corp")) {
			t.Fatalf("%v: org name not made comment safe", name)
		}
		if strings.HasSuffix(name, ".ps1") {
			if !bytes.HasPrefix(data, []byte("\xef\xbb\xbf")) || bytes.Contains(bytes.ReplaceAll(data, []byte("\r\n"), nil), []byte("\n")) {
				t.Fatalf("%v needs a BOM and CRLF line endings", name)
			}
		} else if strings.Contains(text, "\r") {
			t.Fatalf("%v must have Unix line endings", name)
		}
	}

	// The one-liners decode to the scripts.
	m := regexp.MustCompile(`FromBase64String\('([^']+)'\)`).FindStringSubmatch(b.info.Commands.Windows)
	decoded, _ := base64.StdEncoding.DecodeString(m[1])
	windows, _ := b.render(deployWindowsFile)
	if !bytes.Equal(append([]byte("\xef\xbb\xbf"), decoded...), windows) {
		t.Fatal("Windows command does not run the install script")
	}
	m = regexp.MustCompile(`^echo '([^']+)' \| base64 -d \| sudo sh$`).FindStringSubmatch(b.info.Commands.Linux)
	decoded, _ = base64.StdEncoding.DecodeString(m[1])
	linux, _ := b.render(deployLinuxFile)
	if !bytes.Equal(decoded, linux) {
		t.Fatal("Linux command does not run the install script")
	}

	// The Intune package holds the Windows script.
	pkg, err := b.render(deployIntuneFile)
	if err != nil {
		t.Fatal(err)
	}
	info, plain, err := intunewin.Decrypt(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if info.SetupFile != deployWindowsFile {
		t.Fatalf("setup file %v", info.SetupFile)
	}
	zr, err := zip.NewReader(bytes.NewReader(plain), int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	fd, _ := zr.File[0].Open()
	inner, _ := io.ReadAll(fd)
	if zr.File[0].Name != deployWindowsFile || !bytes.Equal(inner, windows) {
		t.Fatal("Intune package does not contain the install script")
	}
}

func TestDeployLocalOnly(t *testing.T) {
	for _, tc := range []struct {
		urls  []string
		local bool
	}{
		{[]string{"https://localhost:8000/"}, true},
		{[]string{"https://127.0.0.1:8000/", "wss://[::1]:8000/"}, true},
		{[]string{"https://127.0.0.1:8000/", "https://10.0.0.5:8000/"}, false},
		{[]string{"https://atl.example.com/"}, false},
	} {
		b, err := newDeployBundle(deployTestConfig(tc.urls...), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if b.info.LocalOnly != tc.local {
			t.Errorf("%v: local only = %v", tc.urls, b.info.LocalOnly)
		}
	}
}

func TestDeployNoClientConfig(t *testing.T) {
	c := deployTestConfig()
	if _, err := newDeployBundle(c, time.Now()); err == nil {
		t.Fatal("org without server URLs accepted")
	}
}
