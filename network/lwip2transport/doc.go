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

/*
The network/lwip2transport package translates between IP packets and TCP/UDP protocols. It uses a [modified lwIP go
library], which is based on the original [lwIP library] (A Lightweight TCP/IP stack). The device is singleton, so only
one instance can be created per process.

To configure the instance with TCP/UDP handlers:

	// tcpHandler will be used to handle TCP streams, and udpHandler to handle UDP packets
	t2s, err := lwip2transport.ConfigureDevice(tcpHandler, udpHandler)
	if err != nil {
		// handle error
	}

[modified lwIP go library]: https://github.com/OutlineFoundation/go-tun2socks
[lwIP library]: https://savannah.nongnu.org/projects/lwip/
*/
package lwip2transport
