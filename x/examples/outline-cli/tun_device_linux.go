// Copyright 2023 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"errors"
	"fmt"

	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"golang.getoutline.org/sdk/network"
)

type tunDevice struct {
	*water.Interface
	link netlink.Link
}

var _ network.IPDevice = (*tunDevice)(nil)

func newTunDevice(name, ip string) (d network.IPDevice, err error) {
	if len(name) == 0 {
		return nil, errors.New("name is required for TUN/TAP device")
	}
	if len(ip) == 0 {
		return nil, errors.New("ip is required for TUN/TAP device")
	}

	tun, err := water.New(water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name:    name,
			Persist: false,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN/TAP device: %w", err)
	}

	defer func() {
		if err != nil {
			tun.Close()
		}
	}()

	tunLink, err := netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("newly created TUN/TAP device '%s' not found: %w", name, err)
	}

	tunDev := &tunDevice{tun, tunLink}
	if err := tunDev.configureSubnet(ip); err != nil {
		return nil, fmt.Errorf("failed to configure TUN/TAP device subnet: %w", err)
	}
	if err := tunDev.bringUp(); err != nil {
		return nil, fmt.Errorf("failed to bring up TUN/TAP device: %w", err)
	}
	return tunDev, nil
}

func (d *tunDevice) MTU() int {
	return 1500
}

func (d *tunDevice) configureSubnet(ip string) error {
	subnet := ip + "/32"
	addr, err := netlink.ParseAddr(subnet)
	if err != nil {
		return fmt.Errorf("subnet address '%s' is not valid: %w", subnet, err)
	}
	if err := netlink.AddrAdd(d.link, addr); err != nil {
		return fmt.Errorf("failed to add subnet to TUN/TAP device '%s': %w", d.Interface.Name(), err)
	}
	return nil
}

func (d *tunDevice) bringUp() error {
	if err := netlink.LinkSetUp(d.link); err != nil {
		return fmt.Errorf("failed to bring TUN/TAP device '%s' up: %w", d.Interface.Name(), err)
	}
	return nil
}
