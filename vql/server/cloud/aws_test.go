package cloud

import (
	"testing"

	"github.com/Velocidex/ordereddict"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSEndpoint(t *testing.T) {
	for _, c := range []struct{ service, region, want string }{
		{"cloudtrail", "eu-west-1", "https://cloudtrail.eu-west-1.amazonaws.com"},
		{"cloudtrail", "us-gov-west-1", "https://cloudtrail.us-gov-west-1.amazonaws.com"},
		{"ec2", "ap-southeast-2", "https://ec2.ap-southeast-2.amazonaws.com"},
		{"iam", "eu-west-1", "https://iam.amazonaws.com"},
		{"iam", "us-gov-east-1", "https://iam.us-gov.amazonaws.com"},
		{"sts", "", "https://sts.amazonaws.com"},
	} {
		got, err := awsEndpoint(c.service, c.region)
		require.NoError(t, err)
		assert.Equal(t, c.want, got)
	}

	for _, region := range []string{
		"evil.example/x", "us-east-1.evil.example", "eu-west-1#", "", "EU-WEST-1",
	} {
		_, err := awsEndpoint("cloudtrail", region)
		assert.Error(t, err, region)
	}
}

func TestAWSUserName(t *testing.T) {
	e := &awsTrailEvent{}
	e.UserIdentity.Type = "AssumedRole"
	e.UserIdentity.ARN = "arn:aws:sts::123456789012:assumed-role/Admin/alice@example.com"
	assert.Equal(t, "Admin/alice@example.com", awsUserName(e))

	e = &awsTrailEvent{}
	e.UserIdentity.Type = "Root"
	assert.Equal(t, "root", awsUserName(e))
}

func TestXMLToDict(t *testing.T) {
	d, err := xmlToDict([]byte(`<ListUsersResponse><ListUsersResult>
        <IsTruncated>true</IsTruncated><Marker>m1</Marker>
        <Users><member><UserName>a</UserName></member><member><UserName>b</UserName></member></Users>
        </ListUsersResult></ListUsersResponse>`))
	require.NoError(t, err)
	result, _ := d.Get("ListUsersResult")
	list, found := awsResultList(result.(*ordereddict.Dict))
	assert.True(t, found)
	assert.Equal(t, 2, len(list))
}
