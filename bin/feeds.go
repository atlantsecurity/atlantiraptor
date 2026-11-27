package main

// "feeds": tools for Atlant Security's side of the premium hunt feeds
// (services/huntfeeds, docs/feeds/README.md). Hidden: customers never
// need them.

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	kingpin "github.com/alecthomas/kingpin/v2"
	"www.velocidex.com/golang/velociraptor/services/huntfeeds"
)

var (
	feeds_command = app.Command("feeds", "Premium hunt feed tools (Atlant Security).").Hidden()

	feeds_keygen_command = feeds_command.Command("keygen", "Make a new feed signing key.")
	feeds_keygen_id      = feeds_keygen_command.Flag("key-id", "Key id, e.g. atlant-feed-2026.").Required().String()
	feeds_keygen_out     = feeds_keygen_command.Flag("out", "Where to write the private key file.").Required().String()

	feeds_check_command = feeds_command.Command("check", "Check a folder of pack files.")
	feeds_check_packs   = feeds_check_command.Arg("packs", "Folder of *.yaml pack files.").Required().String()

	feeds_sign_command  = feeds_command.Command("sign", "Sign a feed for one customer.")
	feeds_sign_key      = feeds_sign_command.Flag("signing-key", "Private key file from keygen.").Required().String()
	feeds_sign_packs    = feeds_sign_command.Flag("packs", "Folder of *.yaml pack files.").Required().String()
	feeds_sign_licence  = feeds_sign_command.Flag("licence-key", "The customer's licence key.").Required().String()
	feeds_sign_id       = feeds_sign_command.Flag("licence-id", "Licence or contract id.").String()
	feeds_sign_customer = feeds_sign_command.Flag("customer", "Customer name shown on their console.").String()
	feeds_sign_plan     = feeds_sign_command.Flag("plan", "Plan name.").Default("Premium").String()
	feeds_sign_expires  = feeds_sign_command.Flag("expires", "End of the paid period (YYYY-MM-DD or RFC3339).").Required().String()
	feeds_sign_lease    = feeds_sign_command.Flag("lease-days", "How long the server may use this feed offline.").Default("14").Int()
	feeds_sign_out      = feeds_sign_command.Flag("out", "Output file (default: standard output).").String()

	feeds_verify_command = feeds_command.Command("verify", "Verify a signed feed with this binary's keys.")
	feeds_verify_file    = feeds_verify_command.Arg("bundle", "Signed feed file.").Required().String()
	feeds_verify_licence = feeds_verify_command.Flag("licence-key", "Also check it was issued for this key.").String()
)

func parseFeedDate(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return t, fmt.Errorf("%q is not YYYY-MM-DD or RFC3339", s)
	}
	// The whole last day is paid for.
	return t.Add(24*time.Hour - time.Second), nil
}

func init() {
	command_handlers = append(command_handlers, func(command string) bool {
		switch command {
		case feeds_keygen_command.FullCommand():
			k, err := huntfeeds.GenerateSigningKey(*feeds_keygen_id)
			kingpin.FatalIfError(err, "keygen")
			data, _ := json.MarshalIndent(k, "", " ")
			f, err := os.OpenFile(*feeds_keygen_out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			kingpin.FatalIfError(err, "writing %v", *feeds_keygen_out)
			_, err = f.Write(data)
			kingpin.FatalIfError(err, "writing %v", *feeds_keygen_out)
			kingpin.FatalIfError(f.Close(), "writing %v", *feeds_keygen_out)
			fmt.Printf("Private key written to %v. Keep it secret (key vault); the feed service signs with it.\n\n", *feeds_keygen_out)
			fmt.Printf("Add this line to feedPublicKeys in services/huntfeeds/keys.go:\n\n\t%q: %q,\n",
				k.KeyID, k.PublicKey)

		case feeds_check_command.FullCommand():
			packs, err := huntfeeds.LoadPacks(*feeds_check_packs)
			kingpin.FatalIfError(err, "packs")
			kingpin.FatalIfError(huntfeeds.CheckPackArtifacts(packs), "artifacts")
			for _, p := range packs {
				fmt.Printf("%-40s v%-3d %-8s %v\n", p.ID, p.Version, p.Severity, p.ArtifactNames())
			}
			fmt.Printf("%d packs OK\n", len(packs))

		case feeds_sign_command.FullCommand():
			key_id, priv, err := huntfeeds.ReadSigningKey(*feeds_sign_key)
			kingpin.FatalIfError(err, "signing key")
			packs, err := huntfeeds.LoadPacks(*feeds_sign_packs)
			kingpin.FatalIfError(err, "packs")
			kingpin.FatalIfError(huntfeeds.CheckPackArtifacts(packs), "artifacts")
			expires, err := parseFeedDate(*feeds_sign_expires)
			kingpin.FatalIfError(err, "expires")
			m, err := huntfeeds.BuildManifest(packs, huntfeeds.IssueOptions{
				LicenceKey: *feeds_sign_licence, LicenceID: *feeds_sign_id,
				Customer: *feeds_sign_customer, Plan: *feeds_sign_plan,
				Expires: expires, Lease: time.Duration(*feeds_sign_lease) * 24 * time.Hour,
			})
			kingpin.FatalIfError(err, "manifest")
			out, err := huntfeeds.SignManifest(m, key_id, priv)
			kingpin.FatalIfError(err, "signing")
			if *feeds_sign_out == "" {
				fmt.Println(string(out))
			} else {
				kingpin.FatalIfError(os.WriteFile(*feeds_sign_out, out, 0644), "writing")
			}

		case feeds_verify_command.FullCommand():
			data, err := os.ReadFile(*feeds_verify_file)
			kingpin.FatalIfError(err, "reading")
			m, err := huntfeeds.Verify(data)
			kingpin.FatalIfError(err, "verify")
			if *feeds_verify_licence != "" {
				kingpin.FatalIfError(m.CheckFor(*feeds_verify_licence, time.Now()), "licence")
			}
			fmt.Printf("OK: %v for %v (%v), %d packs, usable until %v\n", m.Feed,
				m.Licence.Customer, m.Licence.Plan, len(m.Packs),
				m.UsableUntil().UTC().Format(time.RFC3339))

		default:
			return false
		}
		return true
	})
}
