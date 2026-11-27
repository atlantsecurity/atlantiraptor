package huntfeeds

import (
	"crypto/ed25519"
	"encoding/base64"
)

// feedPublicKeys are Atlant Security's feed signing keys (key id ->
// base64 Ed25519 public key). They are fixed at build time: nothing at
// run time can add a key, so only Atlant can publish feed content.
//
// To add a key, run "Atlantiraptor feeds keygen --key-id <id>" on a
// trusted machine, keep the private key file in Atlant's key vault
// (the feed service signs with it), and paste the public key here.
// Keep an old key listed until every bundle signed with it has
// expired, so keys can be rotated without breaking servers.
var feedPublicKeys = map[string]string{
	// "atlant-feed-2026": "<base64 public key>",
}

func publicKeys() map[string]ed25519.PublicKey {
	res := map[string]ed25519.PublicKey{}
	for id, b64 := range feedPublicKeys {
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err == nil && len(raw) == ed25519.PublicKeySize {
			res[id] = ed25519.PublicKey(raw)
		}
	}
	return res
}
