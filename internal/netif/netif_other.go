//go:build !linux

// Stubs so the module compiles on non-Linux build hosts. The real
// implementation is in netif_linux.go; deploy targets are Linux.
package netif

import "errors"

var errUnsupported = errors.New("netif: only supported on linux")

func IfUp(name, cidr string, mtu int) error { return errUnsupported }

type RouteState struct{}

func SetupClientRoutes(serverIP, tunName, dns string) (*RouteState, error) {
	return nil, errUnsupported
}
func (rs *RouteState) Teardown() {}

type SrcRouteState struct{}

func SetupSourceRoute(srcIP, tunName, table string) (*SrcRouteState, error) {
	return nil, errUnsupported
}
func (rs *SrcRouteState) Teardown() {}

type NATState struct{}

func SetupServerNAT(tunName, tunCIDR, wanIface string) (*NATState, error) {
	return nil, errUnsupported
}
func (st *NATState) Teardown() {}
