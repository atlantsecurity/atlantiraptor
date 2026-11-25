package api

// /api/v1/atl/apikeys: console endpoint for server administrators to
// list, create and revoke SIEM/SOAR API keys. It sits behind the normal
// console authentication, CSRF protection and 2FA.

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/velociraptor/acls"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/constants"
	"www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/velociraptor/services"
	"www.velocidex.com/golang/velociraptor/utils"
)

const maxKeyTTLDays = 3650

func apiKeysHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal := ""
		if v, ok := r.Context().Value(constants.GRPC_USER_CONTEXT).(string); ok {
			principal = utils.UnQuote(v)
		}
		org_manager, err := services.GetOrgManager()
		if err != nil {
			groupsJSON(w, http.StatusInternalServerError, map[string]string{"message": "Server not ready."})
			return
		}
		root, err := org_manager.GetOrgConfig(services.ROOT_ORG_ID)
		if err != nil {
			groupsJSON(w, http.StatusInternalServerError, map[string]string{"message": "Server not ready."})
			return
		}
		org_config, err := org_manager.GetOrgConfig(r.Header.Get("Grpc-Metadata-OrgId"))
		if err != nil {
			groupsJSON(w, http.StatusBadRequest, map[string]string{"message": "Unknown org."})
			return
		}
		ok, err := services.CheckAccess(org_config, principal, acls.SERVER_ADMIN)
		if err != nil || !ok {
			groupsJSON(w, http.StatusForbidden, map[string]string{"message": "Only server administrators can manage API keys."})
			return
		}
		audit := func(op string, d *ordereddict.Dict) {
			if err := services.LogAudit(r.Context(), org_config, principal, op, d); err != nil {
				logging.GetLogger(org_config, &logging.FrontendComponent).Error("%v %v", op, principal)
			}
		}

		switch r.Method {
		case http.MethodGet:
			// The CA certificate (public), for clients that must trust
			// this server's self-signed TLS certificate.
			if r.URL.Query().Get("ca") == "1" {
				if root.Client == nil || root.Client.CaCertificate == "" {
					groupsJSON(w, http.StatusNotFound, map[string]string{"message": "No CA certificate in the server config."})
					return
				}
				w.Header().Set("Content-Type", "application/x-pem-file")
				w.Header().Set("Content-Disposition", `attachment; filename="atlantiraptor-ca.pem"`)
				w.Header().Set("Cache-Control", "no-store")
				_, _ = w.Write([]byte(root.Client.CaCertificate))
				return
			}
			keys, err := ListAPIKeys(root)
			if err != nil {
				groupsJSON(w, http.StatusInternalServerError, map[string]string{"message": "Could not read API keys."})
				return
			}
			// Only this org's keys.
			out := []APIKey{}
			for _, k := range keys {
				if k.OrgId == org_config.OrgId || (utils.IsRootOrg(k.OrgId) && utils.IsRootOrg(org_config.OrgId)) {
					out = append(out, k)
				}
			}
			groupsJSON(w, http.StatusOK, map[string]interface{}{"keys": out, "roles": apiKeyRoles,
				"connection": connectionInfo(root)})

		case http.MethodPost:
			var body struct {
				Name            string   `json:"name"`
				Roles           []string `json:"roles"`
				TTLDays         int      `json:"ttl_days"`
				AllowedNetworks []string `json:"allowed_networks"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
				groupsJSON(w, http.StatusBadRequest, map[string]string{"message": "Bad request"})
				return
			}
			if body.TTLDays < 0 || body.TTLDays > maxKeyTTLDays {
				groupsJSON(w, http.StatusBadRequest, map[string]string{"message": "ttl_days must be 0 (no expiry) to 3650"})
				return
			}
			key, token, err := CreateAPIKey(root, org_config, principal, strings.TrimSpace(body.Name),
				body.Roles, time.Duration(body.TTLDays)*24*time.Hour, body.AllowedNetworks...)
			if err != nil {
				groupsJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
				return
			}
			audit("api_key_create", ordereddict.NewDict().Set("key_id", key.ID).Set("name", key.Name).
				Set("roles", key.Roles).Set("expires", key.Expires).Set("allowed_networks", key.AllowedNetworks))
			groupsJSON(w, http.StatusOK, map[string]interface{}{"key": key, "token": token})

		case http.MethodDelete:
			id := r.URL.Query().Get("id")
			keys, err := ListAPIKeys(root)
			if err != nil {
				groupsJSON(w, http.StatusInternalServerError, map[string]string{"message": "Could not read API keys."})
				return
			}
			allowed := false
			for _, k := range keys {
				if k.ID == id && (k.OrgId == org_config.OrgId ||
					(utils.IsRootOrg(k.OrgId) && utils.IsRootOrg(org_config.OrgId))) {
					allowed = true
				}
			}
			if !allowed {
				groupsJSON(w, http.StatusNotFound, map[string]string{"message": "No such key in this org."})
				return
			}
			key, err := RevokeAPIKey(root, id)
			if err != nil {
				groupsJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
				return
			}
			audit("api_key_revoke", ordereddict.NewDict().Set("key_id", key.ID).Set("name", key.Name))
			groupsJSON(w, http.StatusOK, map[string]interface{}{"revoked": key})

		case http.MethodPut:
			// Change the addresses a key may be used from.
			id := r.URL.Query().Get("id")
			if !keyInOrg(root, id, org_config.OrgId) {
				groupsJSON(w, http.StatusNotFound, map[string]string{"message": "No such key in this org."})
				return
			}
			var body struct {
				AllowedNetworks []string `json:"allowed_networks"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
				groupsJSON(w, http.StatusBadRequest, map[string]string{"message": "Bad request"})
				return
			}
			key, err := SetAPIKeyNetworks(root, id, body.AllowedNetworks)
			if err != nil {
				groupsJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
				return
			}
			audit("api_key_networks", ordereddict.NewDict().Set("key_id", key.ID).Set("allowed_networks", key.AllowedNetworks))
			groupsJSON(w, http.StatusOK, map[string]interface{}{"key": key})

		default:
			groupsJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "GET, POST, PUT or DELETE"})
		}
	})
}

// keyInOrg reports whether the key exists and belongs to the org.
func keyInOrg(root *config_proto.Config, id, org_id string) bool {
	keys, err := ListAPIKeys(root)
	if err != nil {
		return false
	}
	for _, k := range keys {
		if k.ID == id && (k.OrgId == org_id || (utils.IsRootOrg(k.OrgId) && utils.IsRootOrg(org_id))) {
			return true
		}
	}
	return false
}

// ConnectionInfo tells an integrator how to reach and trust this server.
type ConnectionInfo struct {
	// The name on the server's TLS certificate. Clients must connect
	// with this name (mapping it to the server's address if needed).
	CertName    string   `json:"cert_name"`
	CertNames   []string `json:"cert_names"`
	CertExpires int64    `json:"cert_expires,omitempty"`
	Port        uint32   `json:"port"`
	BindAddress string   `json:"bind_address"`
	Loopback    bool     `json:"loopback_only"`
	HasCA       bool     `json:"has_ca"`
}

func connectionInfo(root *config_proto.Config) ConnectionInfo {
	info := ConnectionInfo{CertNames: []string{}}
	if root.GUI != nil {
		info.Port = root.GUI.BindPort
		info.BindAddress = root.GUI.BindAddress
		if ip := net.ParseIP(root.GUI.BindAddress); ip != nil && ip.IsLoopback() {
			info.Loopback = true
		}
		if root.GUI.BindAddress == "localhost" {
			info.Loopback = true
		}
	}
	info.HasCA = root.Client != nil && root.Client.CaCertificate != ""
	if root.Frontend != nil && root.Frontend.Certificate != "" {
		if block, _ := pem.Decode([]byte(root.Frontend.Certificate)); block != nil {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				info.CertNames = append(info.CertNames, cert.DNSNames...)
				for _, ip := range cert.IPAddresses {
					info.CertNames = append(info.CertNames, ip.String())
				}
				info.CertExpires = cert.NotAfter.Unix()
				if len(cert.DNSNames) > 0 {
					info.CertName = cert.DNSNames[0]
				} else {
					info.CertName = cert.Subject.CommonName
				}
			}
		}
	}
	return info
}
