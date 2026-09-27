// Copyright 2026 The Outline Authors
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

package quicprelude_test

import (
	"log"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/quicprelude"
)

// The examples compile as part of the tests, so the package documentation
// cannot drift from the API.

func ExampleNewConfig() {
	var inner transport.PacketListener = &transport.UDPListener{}
	listener, err := quicprelude.NewConfig().NewPacketListener(inner)
	if err != nil {
		log.Fatal(err)
	}
	_ = listener
}

func ExampleConfig_WithGenerator() {
	var inner transport.PacketListener = &transport.UDPListener{}
	version, err := quicprelude.FixedVersion(quicprelude.Version2)
	if err != nil {
		log.Fatal(err)
	}
	generator, err := quicprelude.InvalidInitial(version, quicprelude.MatchPacketLength)
	if err != nil {
		log.Fatal(err)
	}
	generator, err = quicprelude.Repeat(2, generator)
	if err != nil {
		log.Fatal(err)
	}
	listener, err := quicprelude.NewConfig().
		WithGenerator(generator).
		NewPacketListener(inner)
	if err != nil {
		log.Fatal(err)
	}
	_ = listener
}
