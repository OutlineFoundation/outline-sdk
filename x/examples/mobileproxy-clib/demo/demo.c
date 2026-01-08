// Copyright 2024 Jigsaw Operations LLC
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

#include <stdio.h>
#include "mobileproxy-clib.h"

int main()
{
  StreamDialer dialer;
  Proxy proxy;

  dialer = NewStreamDialerFromConfig("split:3");
  proxy = RunProxy("127.0.0.1:1234", dialer);

  printf("Running proxy on 127.0.0.1:1234\nPress <Enter> to terminate...");
  getc(stdin);

  // Stop the proxy and clean up
  StopProxy(proxy, 1000);
  ReleaseProxy(proxy);
  ReleaseStreamDialer(dialer);

  return 0;
}
