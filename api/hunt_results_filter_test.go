package api

import (
	"testing"

	api_proto "www.velocidex.com/golang/velociraptor/api/proto"
)

func TestSortHuntRows(t *testing.T) {
	rows := []*api_proto.Row{
		{Json: `["b", 10]`}, {Json: `["a", 2]`}, {Json: `["C", 33]`}, {Json: `[null, 1]`},
	}
	sortRows(rows, 1, false)
	want := []string{`[null, 1]`, `["a", 2]`, `["b", 10]`, `["C", 33]`}
	for i, w := range want {
		if rows[i].Json != w {
			t.Fatalf("numeric asc: row %d = %s, want %s", i, rows[i].Json, w)
		}
	}
	sortRows(rows, 0, true)
	if rows[0].Json != `["C", 33]` || rows[3].Json != `[null, 1]` {
		t.Fatalf("text desc wrong: %v", rows)
	}
}
