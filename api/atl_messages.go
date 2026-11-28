package api

// GET/POST /api/v1/atl/messages: the signed in user's console messages
// (security advisories, announcements and messages from other users),
// grouped and with read/dismissed state. See services/usermessages.
//
// GET ?dismissed=1 also returns dismissed messages.
// POST {"action": "read"|"unread"|"dismiss"|"restore", "ids": [...]}
//      ("*" as an id means every message received so far)
// POST {"action": "clear"} deletes every message.
//
// Every user only ever sees and changes their own messages.

import (
	"encoding/json"
	"net/http"

	"www.velocidex.com/golang/velociraptor/constants"
	"www.velocidex.com/golang/velociraptor/services/usermessages"
	"www.velocidex.com/golang/velociraptor/utils"
)

func messagesHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal := ""
		if v, ok := r.Context().Value(constants.GRPC_USER_CONTEXT).(string); ok {
			principal = utils.UnQuote(v)
		}
		if principal == "" {
			groupsJSON(w, http.StatusUnauthorized, map[string]string{"message": "Not signed in."})
			return
		}

		include_dismissed := r.URL.Query().Get("dismissed") == "1"
		reply := func() {
			summary, err := usermessages.List(r.Context(), principal, include_dismissed)
			if err != nil {
				groupsJSON(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})
				return
			}
			groupsJSON(w, http.StatusOK, summary)
		}

		switch r.Method {
		case http.MethodGet:
			reply()

		case http.MethodPost:
			var body struct {
				Action    string   `json:"action"`
				IDs       []string `json:"ids"`
				Dismissed bool     `json:"dismissed"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&body); err != nil {
				groupsJSON(w, http.StatusBadRequest, map[string]string{"message": "Bad request"})
				return
			}
			include_dismissed = include_dismissed || body.Dismissed

			var err error
			if body.Action == "clear" {
				err = usermessages.Clear(r.Context(), principal)
			} else {
				err = usermessages.MarkMessages(r.Context(), principal, body.Action, body.IDs)
			}
			if err != nil {
				groupsJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
				return
			}
			reply()

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
}
