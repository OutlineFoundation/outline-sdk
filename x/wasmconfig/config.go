// Copyright 2026 The Outline Authors. SPDX-License-Identifier: Apache-2.0
// Package wasmconfig registers the local spike's wasm constructor selectors.
package wasmconfig

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/configurl"
	"golang.getoutline.org/sdk/x/wasm"
)

// Scope is built before use and owns factories and sessions, not injected bases.
// Configuration/build operations are intentionally not concurrent in this spike.
type Scope struct {
	manager   *wasm.Manager
	modules   map[string]*wasm.Session
	digests   map[[32]byte]*wasm.Session
	factories []io.Closer
}

func NewScope(m *wasm.Manager) *Scope {
	return &Scope{manager: m, modules: make(map[string]*wasm.Session), digests: make(map[[32]byte]*wasm.Session)}
}
func (s *Scope) Load(ctx context.Context, id string, data []byte) error {
	if id == "" || s.modules[id] != nil {
		return errors.New("empty or duplicate module ID")
	}
	hash := sha256.Sum256(data)
	session := s.digests[hash]
	if session == nil {
		var e error
		session, e = s.manager.NewSession(ctx, data)
		if e != nil {
			return e
		}
		s.digests[hash] = session
	}
	s.modules[id] = session
	return nil
}
func (s *Scope) Close() error {
	for i := len(s.factories) - 1; i >= 0; i-- {
		s.factories[i].Close()
	}
	s.factories = nil
	for _, session := range s.digests {
		session.Close()
	}
	return nil
}

type spec struct {
	module, component, relay string
	param                    uint32
}

func parse(u url.URL) (spec, error) {
	var out spec
	if u.Host != "" || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return out, errors.New("use wasm:module=ID&component=NAME syntax")
	}
	q, e := url.ParseQuery(u.Opaque)
	if e != nil {
		return out, errors.New("invalid wasm options")
	}
	for k, v := range q {
		if len(v) != 1 {
			return out, fmt.Errorf("duplicate option %s", k)
		}
		switch k {
		case "module", "component", "key", "split", "relay":
		default:
			return out, fmt.Errorf("unknown wasm option %s", k)
		}
	}
	out.module = q.Get("module")
	out.component = q.Get("component")
	out.relay = q.Get("relay")
	if out.module == "" || out.component == "" {
		return out, errors.New("wasm requires module and component")
	}
	if _, ok := q["key"]; ok && !strings.HasSuffix(out.component, ".xor") {
		return out, errors.New("key is only valid for xor constructors")
	}
	if _, ok := q["split"]; ok && out.component != "stream.split" {
		return out, errors.New("split is only valid for stream.split")
	}
	if out.relay != "" && out.component != "stream.xor" {
		return out, errors.New("relay is only valid for stream.xor")
	}
	value := "0"
	if strings.HasSuffix(out.component, ".xor") {
		value = q.Get("key")
		if value == "" {
			value = "37"
		}
	}
	if out.component == "stream.split" {
		value = q.Get("split")
		if value == "" {
			value = "3"
		}
	}
	n, e := strconv.ParseUint(value, 10, 16)
	if e != nil || (out.component == "stream.split" && n == 0) || (strings.HasSuffix(out.component, ".xor") && n > 255) {
		return out, errors.New("invalid constructor numeric parameter")
	}
	out.param = uint32(n)
	return out, nil
}
func (s *Scope) resolve(c *configurl.Config, profile uint32) (spec, *wasm.Session, error) {
	x, e := parse(c.URL)
	if e != nil {
		return x, nil, e
	}
	session := s.modules[x.module]
	if session == nil {
		return x, nil, errors.New("wasm module not loaded")
	}
	kind, e := session.Profile(x.component)
	if e != nil {
		return x, nil, e
	}
	if kind != profile {
		return x, nil, errors.New("unknown constructor or wrong transport interface")
	}
	return x, session, nil
}
func (s *Scope) rollback(mark int) {
	for i := len(s.factories) - 1; i >= mark; i-- {
		s.factories[i].Close()
	}
	s.factories = s.factories[:mark]
}
func (s *Scope) Register(p *configurl.ProviderContainer) {
	p.StreamDialers.RegisterType("wasm", func(ctx context.Context, c *configurl.Config) (transport.StreamDialer, error) {
		x, session, e := s.resolve(c, 1)
		if e != nil {
			return nil, e
		}
		mark := len(s.factories)
		base, e := p.StreamDialers.NewInstance(ctx, c.BaseConfig)
		if e != nil {
			s.rollback(mark)
			return nil, e
		}
		d, e := session.NewStreamDialer(x.component, x.param, x.relay, base)
		if e != nil {
			s.rollback(mark)
			return nil, e
		}
		s.factories = append(s.factories, d)
		return d, nil
	})
	p.PacketListeners.RegisterType("wasm", func(ctx context.Context, c *configurl.Config) (transport.PacketListener, error) {
		x, session, e := s.resolve(c, 2)
		if e != nil {
			return nil, e
		}
		mark := len(s.factories)
		base, e := p.PacketListeners.NewInstance(ctx, c.BaseConfig)
		if e != nil {
			s.rollback(mark)
			return nil, e
		}
		l, e := session.NewPacketListener(x.component, x.param, base)
		if e != nil {
			s.rollback(mark)
			return nil, e
		}
		s.factories = append(s.factories, l)
		return l, nil
	})
}
