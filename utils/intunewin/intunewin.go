// Package intunewin builds Microsoft Intune Win32 app packages
// (.intunewin) without Microsoft's Win32 Content Prep Tool, so the
// server can hand out a package ready to upload to Intune.
//
// A .intunewin file is a zip archive:
//
//	IntuneWinPackage/Contents/IntunePackage.intunewin   the encrypted content
//	IntuneWinPackage/Metadata/Detection.xml             how to decrypt it
//
// The content is a zip of the source folder, encrypted with AES-256-CBC
// (PKCS#7 padding) under a random key and IV, and laid out as
// HMAC-SHA256(32 bytes) | IV(16 bytes) | ciphertext, where the HMAC is
// computed with a second random key over IV | ciphertext.
// Detection.xml carries both keys, the IV, the HMAC and the SHA-256
// digest of the unencrypted zip. The Intune portal reads Detection.xml
// and uploads the encrypted content together with the keys.
package intunewin

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"path"
	"strings"
	"time"
)

// File is one file of the package's source folder.
type File struct {
	Name string // relative path, forward slashes
	Data []byte
}

const (
	contentName = "IntunePackage.intunewin"
	toolVersion = "1.8.6.0"
)

type encryptionInfo struct {
	EncryptionKey        string `xml:"EncryptionKey"`
	MacKey               string `xml:"MacKey"`
	InitializationVector string `xml:"InitializationVector"`
	Mac                  string `xml:"Mac"`
	ProfileIdentifier    string `xml:"ProfileIdentifier"`
	FileDigest           string `xml:"FileDigest"`
	FileDigestAlgorithm  string `xml:"FileDigestAlgorithm"`
}

// ApplicationInfo is the Detection.xml document.
type ApplicationInfo struct {
	XMLName                xml.Name       `xml:"ApplicationInfo"`
	XSD                    string         `xml:"xmlns:xsd,attr"`
	XSI                    string         `xml:"xmlns:xsi,attr"`
	ToolVersion            string         `xml:"ToolVersion,attr"`
	Name                   string         `xml:"Name"`
	UnencryptedContentSize int64          `xml:"UnencryptedContentSize"`
	FileName               string         `xml:"FileName"`
	SetupFile              string         `xml:"SetupFile"`
	EncryptionInfo         encryptionInfo `xml:"EncryptionInfo"`
}

// Build returns a .intunewin package of files; setupFile must be one
// of them (the file Intune's install command runs).
func Build(files []File, setupFile string, modified time.Time) ([]byte, error) {
	found := false
	for _, f := range files {
		if f.Name == setupFile {
			found = true
		}
		if f.Name == "" || strings.HasPrefix(f.Name, "/") || strings.Contains(f.Name, "..") {
			return nil, errors.New("intunewin: bad file name " + f.Name)
		}
	}
	if !found {
		return nil, errors.New("intunewin: setup file is not in the package")
	}

	// 1. The source folder as a zip.
	content := &bytes.Buffer{}
	zw := zip.NewWriter(content)
	for _, f := range files {
		w, err := zw.CreateHeader(&zip.FileHeader{
			Name: f.Name, Method: zip.Deflate, Modified: modified})
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(f.Data); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	plain := content.Bytes()

	// 2. Encrypt and authenticate it.
	key, macKey, iv := make([]byte, 32), make([]byte, 32), make([]byte, aes.BlockSize)
	for _, b := range [][]byte{key, macKey, iv} {
		if _, err := io.ReadFull(rand.Reader, b); err != nil {
			return nil, err
		}
	}
	encrypted, mac, err := encrypt(plain, key, macKey, iv)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(plain)

	b64 := base64.StdEncoding.EncodeToString
	info := ApplicationInfo{
		XSD:                    "http://www.w3.org/2001/XMLSchema",
		XSI:                    "http://www.w3.org/2001/XMLSchema-instance",
		ToolVersion:            toolVersion,
		Name:                   path.Base(setupFile),
		UnencryptedContentSize: int64(len(plain)),
		FileName:               contentName,
		SetupFile:              setupFile,
		EncryptionInfo: encryptionInfo{
			EncryptionKey:        b64(key),
			MacKey:               b64(macKey),
			InitializationVector: b64(iv),
			Mac:                  b64(mac),
			ProfileIdentifier:    "ProfileVersion1",
			FileDigest:           b64(digest[:]),
			FileDigestAlgorithm:  "SHA256",
		},
	}
	detection, err := xml.MarshalIndent(info, "", "  ")
	if err != nil {
		return nil, err
	}
	detection = append([]byte(xml.Header), detection...)

	// 3. The outer package. Like the Content Prep Tool, store without
	// compression: the content is encrypted and would not shrink.
	out := &bytes.Buffer{}
	ow := zip.NewWriter(out)
	for _, e := range []struct {
		name string
		data []byte
	}{
		{"IntuneWinPackage/Contents/" + contentName, encrypted},
		{"IntuneWinPackage/Metadata/Detection.xml", detection},
	} {
		w, err := ow.CreateHeader(&zip.FileHeader{Name: e.name, Method: zip.Store, Modified: modified})
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(e.data); err != nil {
			return nil, err
		}
	}
	if err := ow.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// encrypt returns HMAC | IV | AES-256-CBC(plain) and the HMAC.
func encrypt(plain, key, macKey, iv []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	padded := make([]byte, len(plain)+pad)
	copy(padded, plain)
	for i := len(plain); i < len(padded); i++ {
		padded[i] = byte(pad)
	}

	out := make([]byte, sha256.Size+aes.BlockSize+len(padded))
	copy(out[sha256.Size:], iv)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out[sha256.Size+aes.BlockSize:], padded)

	h := hmac.New(sha256.New, macKey)
	h.Write(out[sha256.Size:])
	mac := h.Sum(nil)
	copy(out, mac)
	return out, mac, nil
}

// Decrypt reverses Build's encryption of the content file given the
// package's Detection.xml; it checks the HMAC and digest. Used by tests
// and to inspect packages.
func Decrypt(pkg []byte) (*ApplicationInfo, []byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(pkg), int64(len(pkg)))
	if err != nil {
		return nil, nil, err
	}
	read := func(name string) ([]byte, error) {
		fd, err := zr.Open(name)
		if err != nil {
			return nil, err
		}
		defer fd.Close()
		return io.ReadAll(fd)
	}
	detection, err := read("IntuneWinPackage/Metadata/Detection.xml")
	if err != nil {
		return nil, nil, err
	}
	info := &ApplicationInfo{}
	if err := xml.Unmarshal(detection, info); err != nil {
		return nil, nil, err
	}
	encrypted, err := read("IntuneWinPackage/Contents/" + info.FileName)
	if err != nil {
		return nil, nil, err
	}
	d := base64.StdEncoding.DecodeString
	key, err1 := d(info.EncryptionInfo.EncryptionKey)
	macKey, err2 := d(info.EncryptionInfo.MacKey)
	mac, err3 := d(info.EncryptionInfo.Mac)
	digest, err4 := d(info.EncryptionInfo.FileDigest)
	if err := errors.Join(err1, err2, err3, err4); err != nil {
		return nil, nil, err
	}
	if len(encrypted) < sha256.Size+2*aes.BlockSize || (len(encrypted)-sha256.Size)%aes.BlockSize != 0 {
		return nil, nil, errors.New("intunewin: bad content length")
	}
	h := hmac.New(sha256.New, macKey)
	h.Write(encrypted[sha256.Size:])
	if !hmac.Equal(h.Sum(nil), mac) || !hmac.Equal(encrypted[:sha256.Size], mac) {
		return nil, nil, errors.New("intunewin: HMAC mismatch")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	iv := encrypted[sha256.Size : sha256.Size+aes.BlockSize]
	plain := make([]byte, len(encrypted)-sha256.Size-aes.BlockSize)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, encrypted[sha256.Size+aes.BlockSize:])
	pad := int(plain[len(plain)-1])
	if pad < 1 || pad > aes.BlockSize {
		return nil, nil, errors.New("intunewin: bad padding")
	}
	plain = plain[:len(plain)-pad]
	sum := sha256.Sum256(plain)
	if !bytes.Equal(sum[:], digest) || int64(len(plain)) != info.UnencryptedContentSize {
		return nil, nil, errors.New("intunewin: digest mismatch")
	}
	return info, plain, nil
}
