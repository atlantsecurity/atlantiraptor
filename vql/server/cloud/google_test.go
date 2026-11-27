package cloud

import (
	"encoding/json"
	"testing"

	"github.com/Velocidex/ordereddict"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGWSParameters(t *testing.T) {
	var raw []json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(`[
      {"name":"login_type","value":"google_password"},
      {"name":"is_suspicious","boolValue":true},
      {"name":"count","intValue":"42"},
      {"name":"scope","multiValue":["a","b"]},
      {"name":"nested","messageValue":{"parameter":[{"name":"x","value":"y"}]}},
      {"name":"empty"}
    ]`), &raw))

	p := gwsParameters(raw)
	v, _ := p.Get("login_type")
	assert.Equal(t, "google_password", v)
	v, _ = p.Get("is_suspicious")
	assert.Equal(t, true, v)
	v, _ = p.Get("count")
	assert.Equal(t, int64(42), v)
	v, _ = p.Get("scope")
	assert.Equal(t, []string{"a", "b"}, v)
	v, _ = p.Get("nested")
	x, _ := v.(*ordereddict.Dict).Get("x")
	assert.Equal(t, "y", x)
	_, pres := p.Get("empty")
	assert.True(t, pres)
}

func TestGWSItems(t *testing.T) {
	page, _ := toDict([]byte(`{"kind":"x","users":[{"a":1}],"nextPageToken":"n"}`))
	items, found := gwsItems(page, "")
	assert.True(t, found)
	assert.Equal(t, 1, len(items))

	// Google leaves out empty lists: with a named field that is no rows,
	// not the page itself.
	empty, _ := toDict([]byte(`{"kind":"x"}`))
	items, found = gwsItems(empty, "users")
	assert.True(t, found)
	assert.Empty(t, items)

	_, found = gwsItems(empty, "")
	assert.False(t, found)
}
