package api

// GET/POST /api/v1/atl/audit: the tamper-evident audit log on the
// server's disk (see services/auditlog). Server administrators of the
// root org only.
//
// GET ?view=status (default)  status, settings and the last check
// GET ?view=entries&...       entries, newest first:
//     from, to (RFC 3339 or unix seconds), principal, operation, org,
//     q (text anywhere in the entry), checkpoints=1, before (seq), limit
// GET ?view=export&format=jsonl|csv&...  the same filters, oldest first,
//     as a download. JSONL lines are exactly as stored, so an unfiltered
//     export can be verified with "audit verify".
// POST {"action": "verify"}                  check the chain now
// POST {"action": "settings", "settings": {...}}

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/velociraptor/acls"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/constants"
	"www.velocidex.com/golang/velociraptor/services"
	"www.velocidex.com/golang/velociraptor/services/auditlog"
	"www.velocidex.com/golang/velociraptor/utils"
)

func parseAuditTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(n, 0), nil
	}
	return time.Parse(time.RFC3339, s)
}

func auditFilter(r *http.Request) (auditlog.Filter, error) {
	q := r.URL.Query()
	from, err := parseAuditTime(q.Get("from"))
	if err != nil {
		return auditlog.Filter{}, fmt.Errorf("from: %w", err)
	}
	to, err := parseAuditTime(q.Get("to"))
	if err != nil {
		return auditlog.Filter{}, fmt.Errorf("to: %w", err)
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	before, _ := strconv.ParseUint(q.Get("before"), 10, 64)
	return auditlog.Filter{
		From:        from,
		To:          to,
		Principal:   q.Get("principal"),
		Operation:   q.Get("operation"),
		OrgId:       q.Get("org"),
		Search:      q.Get("q"),
		Checkpoints: q.Get("checkpoints") == "1" || q.Get("checkpoints") == "true",
		Limit:       limit,
		BeforeSeq:   before,
	}, nil
}

func auditHandler() http.Handler {
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
		if ok, err := services.CheckAccess(root, principal, acls.SERVER_ADMIN); err != nil || !ok {
			groupsJSON(w, http.StatusForbidden, map[string]string{"message": "Only server administrators can open the audit log."})
			return
		}
		service := auditlog.Get()

		switch r.Method {
		case http.MethodGet:
			switch r.URL.Query().Get("view") {
			case "", "status":
				groupsJSON(w, http.StatusOK, service.Status())

			case "entries":
				f, err := auditFilter(r)
				if err != nil {
					groupsJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
					return
				}
				entries, more, err := service.Query(f)
				if err != nil {
					groupsJSON(w, http.StatusServiceUnavailable, map[string]string{"message": err.Error()})
					return
				}
				if entries == nil {
					entries = []*auditlog.Entry{}
				}
				groupsJSON(w, http.StatusOK, map[string]interface{}{"entries": entries, "more": more})

			case "export":
				exportAudit(w, r, root, principal, service)

			default:
				groupsJSON(w, http.StatusBadRequest, map[string]string{"message": "Unknown view"})
			}

		case http.MethodPost:
			var body struct {
				Action   string            `json:"action"`
				Settings auditlog.Settings `json:"settings"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
				groupsJSON(w, http.StatusBadRequest, map[string]string{"message": "Bad request"})
				return
			}
			switch body.Action {
			case "verify":
				service.RunVerify()
				groupsJSON(w, http.StatusOK, service.Status())
			case "settings":
				status, err := service.SetSettings(r.Context(), body.Settings, principal)
				if err != nil {
					groupsJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
					return
				}
				groupsJSON(w, http.StatusOK, status)
			default:
				groupsJSON(w, http.StatusBadRequest, map[string]string{"message": "Unknown action"})
			}

		default:
			groupsJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "GET or POST"})
		}
	})
}

func exportAudit(w http.ResponseWriter, r *http.Request, root *config_proto.Config,
	principal string, service *auditlog.Service) {
	f, err := auditFilter(r)
	if err != nil {
		groupsJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
		return
	}
	if _, err := service.Dir(); err != nil {
		groupsJSON(w, http.StatusServiceUnavailable, map[string]string{"message": err.Error()})
		return
	}
	format := r.URL.Query().Get("format")
	if format != "csv" {
		format = "jsonl"
	}

	// Exporting is itself an audited action.
	_ = services.LogAudit(r.Context(), root, principal, "audit_log_export",
		ordereddict.NewDict().
			Set("format", format).
			Set("from", r.URL.Query().Get("from")).
			Set("to", r.URL.Query().Get("to")).
			Set("principal", f.Principal).
			Set("operation", f.Operation).
			Set("org", f.OrgId).
			Set("q", f.Search).
			Set("remote", r.RemoteAddr))

	name := "atlantiraptor-audit-" + time.Now().UTC().Format("20060102-150405") + "." + format
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)

	if format == "jsonl" {
		w.Header().Set("Content-Type", "application/x-ndjson")
		_ = service.Export(f, func(line []byte, e *auditlog.Entry) error {
			if _, err := w.Write(line); err != nil {
				return err
			}
			_, err := w.Write([]byte("\n"))
			return err
		})
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"seq", "time", "type", "org_id", "principal", "operation", "details", "hash"})
	_ = service.Export(f, func(line []byte, e *auditlog.Entry) error {
		return cw.Write([]string{strconv.FormatUint(e.Seq, 10), e.Time, e.Type, e.OrgId,
			csvSafe(e.Principal), csvSafe(e.Operation), csvSafe(string(e.Details)), e.Hash})
	})
	cw.Flush()
}

// csvSafe stops spreadsheet programs from running a cell as a formula.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}
