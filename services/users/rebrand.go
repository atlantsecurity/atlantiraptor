package users

import (
	"strings"

	"google.golang.org/protobuf/proto"
	"www.velocidex.com/golang/velociraptor/config"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
)

// DocsURL is the Atlantiraptor documentation website.
const DocsURL = "https://atlantsecurity.github.io/atlantiraptor/"

// RebrandLegacyLinks returns the links with the Velociraptor branding
// that older versions wrote into server configurations replaced: a
// link to the Velociraptor documentation now opens the Atlantiraptor
// documentation, and the Velociraptor icon becomes the Atlantiraptor
// icon. Servers keep the GUI links of the configuration they were
// installed with, so without this an updated server would still show
// the old link. The given links are not modified.
func RebrandLegacyLinks(links []*config_proto.GUILink) []*config_proto.GUILink {
	result := make([]*config_proto.GUILink, 0, len(links))
	for _, l := range links {
		if l == nil {
			continue
		}
		if isLegacyDocsURL(l.Url) || l.IconUrl == config.VeloIconDataURL {
			l = proto.Clone(l).(*config_proto.GUILink)
			if isLegacyDocsURL(l.Url) {
				l.Url = DocsURL
			}
			if l.IconUrl == config.VeloIconDataURL {
				l.IconUrl = config.AtlantiraptorIconDataURL
			}
		}
		result = append(result, l)
	}
	return result
}

func isLegacyDocsURL(url string) bool {
	url = strings.ToLower(url)
	return strings.Contains(url, "docs.velociraptor.app") ||
		strings.Contains(url, "velocidex.github.io/velociraptor-docs")
}
