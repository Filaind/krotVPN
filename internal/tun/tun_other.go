//go:build !linux

package tun

import "errors"

var errUnsupported = errors.New("tun: only supported on linux")

// Device is a stub for non-Linux build hosts.
type Device struct{ Name string }

func Open(name string) (*Device, error)       { return nil, errUnsupported }
func (d *Device) Read(b []byte) (int, error)  { return 0, errUnsupported }
func (d *Device) Write(b []byte) (int, error) { return 0, errUnsupported }
func (d *Device) Close() error                { return errUnsupported }
