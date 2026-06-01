//go:build linux

// Package tun creates and reads/writes a layer-3 TUN device carrying raw IP
// packets. Linux only; other platforms get stubs so the module still builds.
package tun

import (
	"fmt"

	"github.com/songgao/water"
)

// Device is a TUN interface.
type Device struct {
	ifce *water.Interface
	Name string
}

// Open creates a TUN device named `name` (requires CAP_NET_ADMIN / root). The
// device comes up unconfigured; address/MTU are set separately by the netif
// package.
func Open(name string) (*Device, error) {
	cfg := water.Config{DeviceType: water.TUN}
	cfg.Name = name
	ifce, err := water.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("create tun %q: %w", name, err)
	}
	return &Device{ifce: ifce, Name: ifce.Name()}, nil
}

func (d *Device) Read(b []byte) (int, error)  { return d.ifce.Read(b) }
func (d *Device) Write(b []byte) (int, error) { return d.ifce.Write(b) }
func (d *Device) Close() error                { return d.ifce.Close() }
