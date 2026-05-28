// Copyright 2024 The Outline Authors
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

//go:build psiphon

/*
Package psiphon provides adaptors to create StreamDialers that leverage [Psiphon] technology and
infrastructure to bypass network interference.

You will need to provide your own Psiphon config file, which you must acquire from the Psiphon team.
See the [Psiphon End-User License Agreement]. For more details, email them at sponsor@psiphon.ca.

For testing, you can [generate a Psiphon config yourself].

# License restrictions

Psiphon code is licensed as GPLv3, which you will have to take into account if you incorporate Psiphon logic into your app.
If you don't want your app to be GPL, consider acquiring an appropriate license when acquiring their services.

Note that a few of Psiphon's dependencies may impose additional restrictions. You can use [go-licenses] to analyze the licenses of your Go code dependencies.

To prevent accidental inclusion of unvetted licenses, you must use the "psiphon" build tag in order to use this package. Typically you do that with
"-tags psiphon".

[Psiphon]: https://psiphon.ca
[Psiphon End-User License Agreement]: https://psiphon.ca/en/license.html
[go-licenses]: https://github.com/google/go-licenses
[generate a Psiphon config yourself]: https://github.com/Psiphon-Labs/psiphon-tunnel-core/tree/master?tab=readme-ov-file#generate-configuration-data
*/
package psiphon
