package cloud

import (
	"context"
	"math"

	"github.com/Velocidex/ordereddict"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	"www.velocidex.com/golang/vfilter"
	"www.velocidex.com/golang/vfilter/arg_parser"
)

type geoDistanceArgs struct {
	Lat1 float64 `vfilter:"required,field=lat1,doc=Latitude of the first point in degrees."`
	Lon1 float64 `vfilter:"required,field=lon1,doc=Longitude of the first point in degrees."`
	Lat2 float64 `vfilter:"required,field=lat2,doc=Latitude of the second point in degrees."`
	Lon2 float64 `vfilter:"required,field=lon2,doc=Longitude of the second point in degrees."`
}

// GeoDistanceFunction returns the great circle distance in kilometres,
// used to find impossible travel between two sign-ins.
type GeoDistanceFunction struct{}

func (self GeoDistanceFunction) Call(ctx context.Context,
	scope vfilter.Scope, args *ordereddict.Dict) vfilter.Any {
	arg := &geoDistanceArgs{}
	err := arg_parser.ExtractArgsWithContext(ctx, scope, args, arg)
	if err != nil {
		scope.Log("geo_distance: %v", err)
		return vfilter.Null{}
	}
	return haversineKm(arg.Lat1, arg.Lon1, arg.Lat2, arg.Lon2)
}

func haversineKm(lat1, lon1, lat2, lon2 float64) float64 {
	const earth_radius_km = 6371.0
	rad := math.Pi / 180
	dlat := (lat2 - lat1) * rad
	dlon := (lon2 - lon1) * rad
	a := math.Sin(dlat/2)*math.Sin(dlat/2) +
		math.Cos(lat1*rad)*math.Cos(lat2*rad)*math.Sin(dlon/2)*math.Sin(dlon/2)
	return 2 * earth_radius_km * math.Asin(math.Min(1, math.Sqrt(a)))
}

func (self GeoDistanceFunction) Info(scope vfilter.Scope,
	type_map *vfilter.TypeMap) *vfilter.FunctionInfo {
	return &vfilter.FunctionInfo{
		Name:    "geo_distance",
		Doc:     "Great circle distance in kilometres between two latitude/longitude points.",
		ArgType: type_map.AddType(scope, &geoDistanceArgs{}),
	}
}

func init() {
	vql_subsystem.RegisterFunction(&GeoDistanceFunction{})
}
