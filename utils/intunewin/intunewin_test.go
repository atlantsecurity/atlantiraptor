package intunewin

import (
	"archive/zip"
	"bytes"
	"io"
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	files := []File{
		{Name: "Install-Atlantiraptor.ps1", Data: []byte("Write-Output hello\r\n")},
		{Name: "README.txt", Data: bytes.Repeat([]byte("x"), 1000)},
	}
	pkg, err := Build(files, "Install-Atlantiraptor.ps1", time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}

	info, plain, err := Decrypt(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if info.SetupFile != "Install-Atlantiraptor.ps1" || info.FileName != "IntunePackage.intunewin" ||
		info.EncryptionInfo.ProfileIdentifier != "ProfileVersion1" || info.EncryptionInfo.FileDigestAlgorithm != "SHA256" {
		t.Fatalf("unexpected Detection.xml: %+v", info)
	}

	zr, err := zip.NewReader(bytes.NewReader(plain), int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	if len(zr.File) != len(files) {
		t.Fatalf("got %d files", len(zr.File))
	}
	for i, f := range zr.File {
		fd, _ := f.Open()
		data, _ := io.ReadAll(fd)
		fd.Close()
		if f.Name != files[i].Name || !bytes.Equal(data, files[i].Data) {
			t.Fatalf("file %d: %q differs", i, f.Name)
		}
	}

	// Every package has fresh keys.
	pkg2, _ := Build(files, "Install-Atlantiraptor.ps1", time.Unix(1700000000, 0))
	info2, _, _ := Decrypt(pkg2)
	if info2.EncryptionInfo.EncryptionKey == info.EncryptionInfo.EncryptionKey {
		t.Fatal("keys reused")
	}
}

func TestTamperedContentIsRejected(t *testing.T) {
	pkg, err := Build([]File{{Name: "a.ps1", Data: []byte("x")}}, "a.ps1", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	// Rewrite the package with one ciphertext byte flipped.
	zr, _ := zip.NewReader(bytes.NewReader(pkg), int64(len(pkg)))
	out := &bytes.Buffer{}
	zw := zip.NewWriter(out)
	for _, f := range zr.File {
		fd, _ := f.Open()
		data, _ := io.ReadAll(fd)
		fd.Close()
		if f.Name == "IntuneWinPackage/Contents/IntunePackage.intunewin" {
			data[len(data)-1] ^= 0xff
		}
		w, _ := zw.Create(f.Name)
		w.Write(data)
	}
	zw.Close()
	bad := out.Bytes()
	if _, _, err := Decrypt(bad); err == nil {
		t.Fatal("tampered package accepted")
	}
}

func TestBadInput(t *testing.T) {
	if _, err := Build([]File{{Name: "a.ps1"}}, "b.ps1", time.Now()); err == nil {
		t.Fatal("missing setup file accepted")
	}
	if _, err := Build([]File{{Name: "../a.ps1"}}, "../a.ps1", time.Now()); err == nil {
		t.Fatal("path traversal accepted")
	}
}
