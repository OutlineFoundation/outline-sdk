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

package transport

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type collectStreamDialer struct {
	Dialer StreamDialer
	Addrs  []string
}

func (d *collectStreamDialer) DialStream(ctx context.Context, addr string) (StreamConn, error) {
	d.Addrs = append(d.Addrs, addr)
	return d.Dialer.DialStream(ctx, addr)
}

var nilDialer = FuncStreamDialer(func(ctx context.Context, addr string) (StreamConn, error) {
	return nil, nil
})

func newErrorStreamDialer(err error) StreamDialer {
	return FuncStreamDialer(func(ctx context.Context, addr string) (StreamConn, error) {
		return nil, err
	})
}

func TestHappyEyeballsStreamDialer_DialStream(t *testing.T) {
	t.Run("Works with IPv4 hosts", func(t *testing.T) {
		baseDialer := collectStreamDialer{Dialer: nilDialer}
		dialer := HappyEyeballsStreamDialer{Dialer: &baseDialer}
		_, err := dialer.DialStream(context.Background(), "8.8.8.8:53")
		require.NoError(t, err)
		require.Equal(t, []string{"8.8.8.8:53"}, baseDialer.Addrs)
	})

	t.Run("Works with IPv6 hosts", func(t *testing.T) {
		baseDialer := collectStreamDialer{Dialer: nilDialer}
		dialer := HappyEyeballsStreamDialer{Dialer: &baseDialer}
		_, err := dialer.DialStream(context.Background(), "[2001:4860:4860::8888]:53")
		require.NoError(t, err)
		require.Equal(t, []string{"[2001:4860:4860::8888]:53"}, baseDialer.Addrs)
	})

	t.Run("Prefer IPv6", func(t *testing.T) {
		baseDialer := collectStreamDialer{Dialer: nilDialer}
		dialer := HappyEyeballsStreamDialer{
			Dialer: &baseDialer,
			Resolve: func(ctx context.Context, hostname string) <-chan HappyEyeballsResolution {
				resultsCh := make(chan HappyEyeballsResolution, 2)
				resultsCh <- HappyEyeballsResolution{[]netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil}
				resultsCh <- HappyEyeballsResolution{[]netip.Addr{netip.MustParseAddr("2001:4860:4860::8888")}, nil}
				close(resultsCh)
				return resultsCh
			},
		}
		_, err := dialer.DialStream(context.Background(), "dns.google:53")
		require.NoError(t, err)
		require.Equal(t, []string{"[2001:4860:4860::8888]:53"}, baseDialer.Addrs)
	})

	t.Run("Prefer IPv6 if there's a small delay", func(t *testing.T) {
		baseDialer := collectStreamDialer{Dialer: nilDialer}
		dialer := HappyEyeballsStreamDialer{
			Dialer: &baseDialer,
			Resolve: NewParallelHappyEyeballsResolveFunc(
				func(ctx context.Context, host string) ([]netip.Addr, error) {
					time.Sleep(10 * time.Millisecond)
					return []netip.Addr{netip.MustParseAddr("2001:4860:4860::8888")}, nil
				},
				func(ctx context.Context, host string) ([]netip.Addr, error) {
					return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
				},
			),
		}
		_, err := dialer.DialStream(context.Background(), "dns.google:53")
		require.NoError(t, err)
		require.Equal(t, []string{"[2001:4860:4860::8888]:53"}, baseDialer.Addrs)
	})

	t.Run("Use IPv4 if IPv6 hangs, with fallback", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		baseDialer := collectStreamDialer{Dialer: FuncStreamDialer(func(ctx context.Context, addr string) (StreamConn, error) {
			if addr == "8.8.8.8:53" {
				return nil, errors.New("failed to dial")
			}
			return nil, nil
		})}
		dialer := HappyEyeballsStreamDialer{
			Dialer: &baseDialer,
			Resolve: NewParallelHappyEyeballsResolveFunc(
				func(ctx context.Context, host string) ([]netip.Addr, error) {
					// Make it hang.
					<-ctx.Done()
					return []netip.Addr{netip.MustParseAddr("2001:4860:4860::8888")}, nil
				},
				func(ctx context.Context, host string) ([]netip.Addr, error) {
					return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("8.8.4.4")}, nil
				},
			),
		}
		_, err := dialer.DialStream(ctx, "dns.google:53")
		require.NoError(t, err)
		require.Equal(t, []string{"8.8.8.8:53", "8.8.4.4:53"}, baseDialer.Addrs)
	})

	t.Run("Use IPv6 if IPv4 fails", func(t *testing.T) {
		baseDialer := collectStreamDialer{Dialer: nilDialer}
		dialer := HappyEyeballsStreamDialer{
			Dialer: &baseDialer,
			Resolve: NewParallelHappyEyeballsResolveFunc(
				func(ctx context.Context, host string) ([]netip.Addr, error) {
					time.Sleep(10 * time.Millisecond)
					return []netip.Addr{netip.MustParseAddr("2001:4860:4860::8888")}, nil

				},
				func(ctx context.Context, host string) ([]netip.Addr, error) {
					return nil, errors.New("lookup failed")
				},
			),
		}
		_, err := dialer.DialStream(context.Background(), "dns.google:53")
		require.NoError(t, err)
		require.Equal(t, []string{"[2001:4860:4860::8888]:53"}, baseDialer.Addrs)
	})

	t.Run("Use IPv4 if IPv6 fails", func(t *testing.T) {
		baseDialer := collectStreamDialer{Dialer: nilDialer}
		dialer := HappyEyeballsStreamDialer{
			Dialer: &baseDialer,
			Resolve: NewParallelHappyEyeballsResolveFunc(
				func(ctx context.Context, host string) ([]netip.Addr, error) {
					return nil, errors.New("lookup failed")
				},
				func(ctx context.Context, host string) ([]netip.Addr, error) {
					time.Sleep(10 * time.Millisecond)
					return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
				},
			),
		}
		_, err := dialer.DialStream(context.Background(), "dns.google:53")
		require.NoError(t, err)
		require.Equal(t, []string{"8.8.8.8:53"}, baseDialer.Addrs)
	})

	t.Run("No dial if lookup fails", func(t *testing.T) {
		baseDialer := collectStreamDialer{Dialer: nilDialer}
		dialer := HappyEyeballsStreamDialer{
			Dialer: &baseDialer,
			Resolve: NewParallelHappyEyeballsResolveFunc(
				func(ctx context.Context, host string) ([]netip.Addr, error) {
					return nil, errors.New("lookup failed")
				},
				func(ctx context.Context, host string) ([]netip.Addr, error) {
					return nil, errors.New("lookup failed")
				},
			),
		}
		_, err := dialer.DialStream(context.Background(), "dns.google:53")
		require.Error(t, err)
		require.Empty(t, baseDialer.Addrs)
	})

	t.Run("No IPs returned", func(t *testing.T) {
		baseDialer := collectStreamDialer{Dialer: nilDialer}
		dialer := HappyEyeballsStreamDialer{
			Dialer: &baseDialer,
			Resolve: NewParallelHappyEyeballsResolveFunc(
				func(ctx context.Context, host string) ([]netip.Addr, error) {
					return []netip.Addr{}, nil
				},
				func(ctx context.Context, host string) ([]netip.Addr, error) {
					return []netip.Addr{}, nil
				},
			),
		}
		_, err := dialer.DialStream(context.Background(), "dns.google:53")
		require.Error(t, err)
		require.Empty(t, baseDialer.Addrs)
	})

	t.Run("Fallback to second address", func(t *testing.T) {
		var dialedAddrs []string
		dialer := HappyEyeballsStreamDialer{
			Dialer: FuncStreamDialer(func(ctx context.Context, addr string) (StreamConn, error) {
				dialedAddrs = append(dialedAddrs, addr)
				if addr == "[2001:4860:4860::8888]:53" {
					return nil, errors.New("dial failed")
				}
				return nil, nil
			}),
			Resolve: NewParallelHappyEyeballsResolveFunc(
				func(ctx context.Context, host string) ([]netip.Addr, error) {
					return []netip.Addr{netip.MustParseAddr("2001:4860:4860::8888")}, nil
				},
				func(ctx context.Context, host string) ([]netip.Addr, error) {
					return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
				},
			),
		}
		_, err := dialer.DialStream(context.Background(), "dns.google:53")
		require.NoError(t, err)
		require.Equal(t, []string{"[2001:4860:4860::8888]:53", "8.8.8.8:53"}, dialedAddrs)
	})

	/* Commenting out flaky test until we have time to fix the race condition
	t.Run("IP order", func(t *testing.T) {
		waitForIPv4Ch := make(chan struct{})
		dialFailErr := errors.New("failed to dial")
		baseDialer := collectStreamDialer{Dialer: FuncStreamDialer(func(ctx context.Context, addr string) (StreamConn, error) {
			ap, err := netip.ParseAddrPort(addr)
			require.NoError(t, err)
			if ap.Addr().Is4() {
				select {
				case <-waitForIPv4Ch:
					// Avoids closing a closed channel.
				default:
					close(waitForIPv4Ch)
				}
			} else {
				// We block IPv6 dials until we have IPv4 results. Otherwise all IPv6 dials may proceed before the IPv4 results
				// are processed, resulting on a race condition.
				<-waitForIPv4Ch
			}
			time.Sleep(time.Microsecond)
			return nil, dialFailErr
		})}
		dialer := HappyEyeballsStreamDialer{
			Dialer: &baseDialer,
			Resolve: NewParallelHappyEyeballsResolveFunc(
				func(ctx context.Context, host string) ([]netip.Addr, error) {
					return []netip.Addr{
						netip.MustParseAddr("::1"),
						netip.MustParseAddr("::2"),
						netip.MustParseAddr("::3"),
					}, nil
				},
				func(ctx context.Context, host string) ([]netip.Addr, error) {
					return []netip.Addr{
						netip.MustParseAddr("1.1.1.1"),
						netip.MustParseAddr("2.2.2.2"),
						netip.MustParseAddr("3.3.3.3"),
					}, nil
				},
			),
		}
		_, err := dialer.DialStream(context.Background(), "dns.google:53")
		require.ErrorIs(t, err, dialFailErr)
		require.Equal(t, []string{"[::1]:53", "1.1.1.1:53", "[::2]:53", "2.2.2.2:53", "[::3]:53", "3.3.3.3:53"}, baseDialer.Addrs)
	})
	*/

	t.Run("Cancelled lookups", func(t *testing.T) {
		var hold sync.WaitGroup
		hold.Add(1)
		defer hold.Done()
		ctx, cancel := context.WithCancel(context.Background())
		baseDialer := collectStreamDialer{Dialer: nilDialer}
		dialer := HappyEyeballsStreamDialer{
			Dialer: &baseDialer,
			Resolve: NewParallelHappyEyeballsResolveFunc(
				func(ctx context.Context, host string) ([]netip.Addr, error) {
					hold.Wait()
					return []netip.Addr{netip.MustParseAddr("2001:4860:4860::8888")}, nil
				},
				func(ctx context.Context, host string) ([]netip.Addr, error) {
					cancel()
					hold.Wait()
					return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
				},
			),
		}
		_, err := dialer.DialStream(ctx, "dns.google:53")
		require.ErrorIs(t, err, context.Canceled)
		require.Empty(t, baseDialer.Addrs)
	})

	t.Run("Cancelled dial", func(t *testing.T) {
		var hold sync.WaitGroup
		hold.Add(1)
		defer hold.Done()
		ctx, cancel := context.WithCancel(context.Background())
		baseDialer := collectStreamDialer{Dialer: FuncStreamDialer(func(ctx context.Context, addr string) (StreamConn, error) {
			go cancel()
			hold.Wait()
			return nil, nil
		})}
		dialer := HappyEyeballsStreamDialer{
			Dialer: &baseDialer,
			Resolve: NewParallelHappyEyeballsResolveFunc(
				func(ctx context.Context, host string) ([]netip.Addr, error) {
					return []netip.Addr{netip.MustParseAddr("2001:4860:4860::8888")}, nil
				},
				func(ctx context.Context, host string) ([]netip.Addr, error) {
					return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
				},
			),
		}
		_, err := dialer.DialStream(ctx, "dns.google:53")
		require.ErrorIs(t, err, context.Canceled)
		require.Equal(t, []string{"[2001:4860:4860::8888]:53"}, baseDialer.Addrs)
	})

	t.Run("Bad address", func(t *testing.T) {
		dialer := HappyEyeballsStreamDialer{Dialer: nilDialer}
		_, err := dialer.DialStream(context.Background(), "invalid address")
		require.Error(t, err)
	})
}

func ExampleNewParallelHappyEyeballsResolveFunc() {
	ips := []netip.Addr{}
	dialer := HappyEyeballsStreamDialer{
		Dialer: FuncStreamDialer(func(ctx context.Context, addr string) (StreamConn, error) {
			ips = append(ips, netip.MustParseAddrPort(addr).Addr())
			// Add a slight delay to simulate a more real life ordering.
			time.Sleep(1 * time.Millisecond)
			return nil, errors.New("not implemented")
		}),
		Resolve: NewParallelHappyEyeballsResolveFunc(
			func(ctx context.Context, hostname string) ([]netip.Addr, error) {
				return []netip.Addr{
					netip.MustParseAddr("2001:4860:4860::8844"),
					netip.MustParseAddr("2001:4860:4860::8888"),
				}, nil
			},
			func(ctx context.Context, hostname string) ([]netip.Addr, error) {
				return []netip.Addr{
					netip.MustParseAddr("8.8.8.8"),
					netip.MustParseAddr("8.8.4.4"),
				}, nil
			},
		),
	}
	dialer.DialStream(context.Background(), "dns.google:53")
	fmt.Println(ips)
	// Output:
	// [2001:4860:4860::8844 8.8.8.8 2001:4860:4860::8888 8.8.4.4]
}

func ExampleHappyEyeballsStreamDialer_fixedResolution() {
	ips := []netip.Addr{}
	dialer := HappyEyeballsStreamDialer{
		Dialer: FuncStreamDialer(func(ctx context.Context, addr string) (StreamConn, error) {
			ips = append(ips, netip.MustParseAddrPort(addr).Addr())
			return nil, errors.New("not implemented")
		}),
		Resolve: func(ctx context.Context, hostname string) <-chan HappyEyeballsResolution {
			resultCh := make(chan HappyEyeballsResolution, 1)
			defer close(resultCh)
			resultCh <- HappyEyeballsResolution{
				IPs: []netip.Addr{
					netip.MustParseAddr("2001:4860:4860::8844"),
					netip.MustParseAddr("2001:4860:4860::8888"),
					netip.MustParseAddr("8.8.8.8"),
					netip.MustParseAddr("8.8.4.4"),
				},
				Err: nil,
			}
			return resultCh
		},
	}
	dialer.DialStream(context.Background(), "dns.google:53")
	fmt.Println(ips)
	// Output:
	// [2001:4860:4860::8844 8.8.8.8 2001:4860:4860::8888 8.8.4.4]
}

func ExampleHappyEyeballsStreamDialer_dualStack() {
	// Fixed resolutions to make the example work consistently without network access.
	resolveIPv6 := func(ctx context.Context, hostname string) ([]netip.Addr, error) {
		// Illustrative delay to show that IPv6 is preferred even if it arrives shortly
		// after IPv4.
		time.Sleep(10 * time.Millisecond)
		return []netip.Addr{
			netip.MustParseAddr("2001:4860:4860::8844"),
			netip.MustParseAddr("2001:4860:4860::8888"),
		}, nil
	}
	resolveIPv4 := func(ctx context.Context, hostname string) ([]netip.Addr, error) {
		return []netip.Addr{
			netip.MustParseAddr("8.8.8.8"),
			netip.MustParseAddr("8.8.4.4"),
		}, nil
	}

	ips := []netip.Addr{}
	dialer := HappyEyeballsStreamDialer{
		Dialer: FuncStreamDialer(func(ctx context.Context, addr string) (StreamConn, error) {
			ips = append(ips, netip.MustParseAddrPort(addr).Addr())
			return nil, errors.New("not implemented")
		}),

		// This function mimics that created with NewParallelHappyEyeballsResolveFunc.
		Resolve: func(ctx context.Context, hostname string) <-chan HappyEyeballsResolution {
			// Use a buffered channel with space for both lookups, to ensure the goroutines won't
			// block on channel write if the Happy Eyeballs algorithm is cancelled and no longer reading.
			resultsCh := make(chan HappyEyeballsResolution, 2)
			// Used to tell the IPv4 goroutine that the IPv6 one is done, so we can safely
			// close resultsCh.
			v6DoneCh := make(chan struct{})

			// Run IPv6 resolution.
			go func(hostname string) {
				// Notify the IPv4 goroutine that the IPv6 is done.
				defer close(v6DoneCh)
				ips, err := resolveIPv6(ctx, hostname)
				resultsCh <- HappyEyeballsResolution{ips, err}
			}(hostname)

			// Run IPv4 resolution.
			go func(hostname string) {
				ips, err := resolveIPv4(ctx, hostname)
				resultsCh <- HappyEyeballsResolution{ips, err}
				// Wait for the IPv6 resolution before closing the channel.
				<-v6DoneCh
				close(resultsCh)
			}(hostname)

			// Return the channel quickly, before resolutions are done.
			return resultsCh
		},
	}
	dialer.DialStream(context.Background(), "dns.google:53")
	fmt.Println(ips)
	// Output:
	// [2001:4860:4860::8844 8.8.8.8 2001:4860:4860::8888 8.8.4.4]
}
