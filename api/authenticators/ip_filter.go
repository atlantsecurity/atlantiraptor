package authenticators

import (
	"net"
	"net/http"

	api_utils "www.velocidex.com/golang/velociraptor/api/utils"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
)

// Implement a src IP filter if required. This adds an additional
// layer of protection on the GUI.
func IpFilter(config_obj *config_proto.Config,
	next http.Handler) http.Handler {

	// The run-time allowlists (Admin > Network access) apply after the
	// static GUI.allowed_cidr list in the config file.
	parent := http.Handler(networkAllowlistGate(config_obj, next))

	if config_obj.GUI == nil || len(config_obj.GUI.AllowedCidr) == 0 {
		return api_utils.HandlerFunc(next, parent.ServeHTTP)
	}

	ranges := []*net.IPNet{}
	for _, cidr := range config_obj.GUI.AllowedCidr {
		_, cidr_net, err := net.ParseCIDR(cidr)
		if err != nil {
			// Should never happen because sanity service should check
			// it already.
			panic("Invalid CIDR Range " + cidr)
		}
		ranges = append(ranges, cidr_net)
	}

	return api_utils.HandlerFunc(next,
		func(w http.ResponseWriter, r *http.Request) {

			// One address: the socket peer, or the proxy-added forwarded
			// entry when a proxy header is configured (see ClientIP).
			if ip := ClientIP(config_obj, r); ip != nil && matchCidr(ranges, ip.String()) {
				parent.ServeHTTP(w, r)
				return
			}
			http.Error(w, "rejected", http.StatusUnauthorized)
		})
}

func matchCidr(ranges []*net.IPNet, ip_strings ...string) bool {
	for _, ip_str := range ip_strings {
		ip := net.ParseIP(ip_str)
		if ip == nil {
			return false
		}

		for _, cidr := range ranges {
			if cidr.Contains(ip) {
				return true
			}
		}
	}
	return false
}
