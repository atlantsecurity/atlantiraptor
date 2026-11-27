package api

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Velocidex/ordereddict"
	api_proto "www.velocidex.com/golang/velociraptor/api/proto"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/json"
)

// Sorting needs every matching row in memory, so it is limited to this
// many matches. Filtering alone streams and has no limit.
const maxSortedHuntRows = 200000

// filteredHuntResults pages through every row of a hunt source,
// keeping rows that match filter (any cell, case-insensitive) and
// optionally sorting them, so the console's search and sort cover the
// whole hunt rather than only the rows already loaded in the browser.
// total_rows in the response is the number of matching rows.
func filteredHuntResults(
	ctx context.Context, config_obj *config_proto.Config, principal string,
	in *api_proto.GetHuntResultsRequest, count uint64) (*api_proto.GetTableResponse, error) {

	var re *regexp.Regexp
	if in.Filter != "" {
		var err error
		re, err = regexp.Compile("(?i)" + in.Filter)
		if err != nil {
			// Not a valid regex: match it as plain text.
			re = regexp.MustCompile("(?i)" + regexp.QuoteMeta(in.Filter))
		}
	}

	env := ordereddict.NewDict().
		Set("HuntID", in.HuntId).
		Set("ArtifactName", in.Artifact)
	all, err := RunVQL(ctx, config_obj, principal, env,
		"SELECT * FROM hunt_results(hunt_id=HuntID, artifact=ArtifactName)")
	if err != nil {
		return nil, err
	}

	matched := make([]*api_proto.Row, 0, len(all.Rows))
	for _, row := range all.Rows {
		if re == nil || re.MatchString(row.Json) {
			matched = append(matched, row)
		}
	}

	if in.SortColumn != "" {
		if len(matched) > maxSortedHuntRows {
			return nil, fmt.Errorf(
				"%d rows match; filter to fewer than %d rows to sort them",
				len(matched), maxSortedHuntRows)
		}
		idx := -1
		for i, c := range all.Columns {
			if c == in.SortColumn {
				idx = i
				break
			}
		}
		if idx >= 0 {
			sortRows(matched, idx, in.SortDesc)
		}
	}

	result := &api_proto.GetTableResponse{
		Columns:   all.Columns,
		TotalRows: int64(len(matched)),
	}
	start := in.Offset
	if start > uint64(len(matched)) {
		start = uint64(len(matched))
	}
	end := start + count
	if end > uint64(len(matched)) {
		end = uint64(len(matched))
	}
	result.Rows = matched[start:end]
	return result, nil
}

type sortKey struct {
	num   float64
	isNum bool
	str   string
}

func cellKey(row *api_proto.Row, idx int) sortKey {
	var cells []interface{}
	if err := json.Unmarshal([]byte(row.Json), &cells); err != nil || idx >= len(cells) {
		return sortKey{}
	}
	switch v := cells[idx].(type) {
	case float64:
		return sortKey{num: v, isNum: true}
	case int64:
		return sortKey{num: float64(v), isNum: true}
	case nil:
		return sortKey{}
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return sortKey{num: f, isNum: true, str: v}
		}
		return sortKey{str: strings.ToLower(v)}
	default:
		s, _ := json.Marshal(v)
		return sortKey{str: strings.ToLower(string(s))}
	}
}

func sortRows(rows []*api_proto.Row, idx int, desc bool) {
	keys := make([]sortKey, len(rows))
	for i, r := range rows {
		keys[i] = cellKey(r, idx)
	}
	order := make([]int, len(rows))
	for i := range order {
		order[i] = i
	}
	less := func(a, b sortKey) bool {
		if a.isNum && b.isNum {
			return a.num < b.num
		}
		if a.isNum != b.isNum {
			// Numbers before text.
			return a.isNum
		}
		return a.str < b.str
	}
	sort.SliceStable(order, func(i, j int) bool {
		a, b := keys[order[i]], keys[order[j]]
		if desc {
			return less(b, a)
		}
		return less(a, b)
	})
	sorted := make([]*api_proto.Row, len(rows))
	for i, o := range order {
		sorted[i] = rows[o]
	}
	copy(rows, sorted)
}
