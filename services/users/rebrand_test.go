package users

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"www.velocidex.com/golang/velociraptor/config"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
)

func TestRebrandLegacyLinks(t *testing.T) {
	legacy := &config_proto.GUILink{
		Text:    "Documentation",
		Url:     "https://docs.velociraptor.app/",
		Type:    "sidebar",
		IconUrl: config.VeloIconDataURL,
	}
	other := &config_proto.GUILink{
		Text:    "Wiki",
		Url:     "https://wiki.example.com/",
		IconUrl: config.VeloIconDataURL,
	}
	untouched := &config_proto.GUILink{
		Text: "VirusTotal",
		Url:  "https://www.virustotal.com/gui/search/",
	}

	got := RebrandLegacyLinks([]*config_proto.GUILink{legacy, nil, other, untouched})
	assert.Equal(t, 3, len(got))

	assert.Equal(t, DocsURL, got[0].Url)
	assert.Equal(t, config.AtlantiraptorIconDataURL, got[0].IconUrl)
	assert.Equal(t, "Documentation", got[0].Text)

	// Only the icon of a custom link changes.
	assert.Equal(t, "https://wiki.example.com/", got[1].Url)
	assert.Equal(t, config.AtlantiraptorIconDataURL, got[1].IconUrl)

	assert.Same(t, untouched, got[2])

	// The configuration itself is not modified.
	assert.Equal(t, "https://docs.velociraptor.app/", legacy.Url)
	assert.Equal(t, config.VeloIconDataURL, legacy.IconUrl)
}
