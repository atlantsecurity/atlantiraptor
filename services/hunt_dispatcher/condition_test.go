package hunt_dispatcher

import (
	"testing"

	"github.com/stretchr/testify/assert"
	api_proto "www.velocidex.com/golang/velociraptor/api/proto"
)

func labelCondition(include, exclude []string) *api_proto.HuntCondition {
	cond := &api_proto.HuntCondition{}
	if include != nil {
		cond.UnionField = &api_proto.HuntCondition_Labels{
			Labels: &api_proto.HuntLabelCondition{Label: include},
		}
	}
	if exclude != nil {
		cond.ExcludedLabels = &api_proto.HuntLabelCondition{Label: exclude}
	}
	return cond
}

func TestNormalizeHuntCondition(t *testing.T) {
	// Empty label conditions are removed entirely.
	hunt := &api_proto.Hunt{Condition: labelCondition(
		[]string{}, []string{"", " "})}
	normalizeHuntCondition(hunt)
	assert.Nil(t, hunt.Condition)

	// Empty include labels with a real exclude label keep only the
	// exclude condition.
	hunt = &api_proto.Hunt{Condition: labelCondition(
		[]string{""}, []string{"Excluded"})}
	normalizeHuntCondition(hunt)
	assert.Nil(t, hunt.Condition.GetLabels())
	assert.Equal(t, []string{"Excluded"}, hunt.Condition.ExcludedLabels.Label)

	// Real labels are kept, empty ones dropped.
	hunt = &api_proto.Hunt{Condition: labelCondition(
		[]string{"", "Label1"}, nil)}
	normalizeHuntCondition(hunt)
	assert.Equal(t, []string{"Label1"}, hunt.Condition.GetLabels().Label)
	assert.Nil(t, hunt.Condition.ExcludedLabels)

	// OS conditions are untouched.
	hunt = &api_proto.Hunt{Condition: &api_proto.HuntCondition{
		UnionField: &api_proto.HuntCondition_Os{
			Os: &api_proto.HuntOsCondition{Os: api_proto.HuntOsCondition_LINUX},
		},
	}}
	normalizeHuntCondition(hunt)
	assert.Equal(t, api_proto.HuntOsCondition_LINUX, hunt.Condition.GetOs().Os)
}
