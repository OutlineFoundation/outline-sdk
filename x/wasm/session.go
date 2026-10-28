// Copyright 2026 The Outline Authors. SPDX-License-Identifier: Apache-2.0
package wasm

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

const BufferSize = 65536
const MaxPayload = BufferSize - 8
const maxArtifact = 4 << 20

// Manager owns a runtime and compiled code. It is never global.
type Manager struct {
	mu       sync.Mutex
	rt       wazero.Runtime
	code     map[[32]byte]wazero.CompiledModule
	sessions []*Session
	closed   bool
}

func NewManager(ctx context.Context, compiler bool) *Manager {
	cfg := wazero.NewRuntimeConfigInterpreter()
	if compiler {
		cfg = wazero.NewRuntimeConfig()
	}
	cfg = cfg.WithMemoryLimitPages(256).WithCloseOnContextDone(true)
	return &Manager{rt: wazero.NewRuntimeWithConfig(ctx, cfg), code: make(map[[32]byte]wazero.CompiledModule)}
}
func (m *Manager) CompiledCount() int { m.mu.Lock(); defer m.mu.Unlock(); return len(m.code) }
func (m *Manager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	ss := append([]*Session(nil), m.sessions...)
	m.mu.Unlock()
	for _, s := range ss {
		s.Close()
	}
	return m.rt.Close(context.Background())
}

// Session is an explicit shared memory/failure boundary, not a dialer singleton.
type Session struct {
	mu             sync.Mutex
	module         api.Module
	ctx            context.Context
	cancel         context.CancelFunc
	arena, scratch uint32
	functions      map[string]api.Function
	calls          uint64
}

func (m *Manager) NewSession(ctx context.Context, data []byte) (*Session, error) {
	if len(data) == 0 || len(data) > maxArtifact {
		return nil, errors.New("wasm artifact size out of bounds")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, errors.New("wasm manager closed")
	}
	digest := sha256.Sum256(data)
	code := m.code[digest]
	if code == nil {
		var err error
		code, err = m.rt.CompileModule(ctx, data)
		if err != nil {
			return nil, fmt.Errorf("compile wasm: %w", err)
		}
		if len(code.ImportedFunctions()) != 0 || len(code.ImportedMemories()) != 0 {
			code.Close(ctx)
			return nil, errors.New("spike ABI permits no imports")
		}
		m.code[digest] = code
	}
	mod, err := m.rt.InstantiateModule(ctx, code, wazero.NewModuleConfig().WithName("").WithStartFunctions())
	if err != nil {
		return nil, err
	}
	life, cancel := context.WithCancel(context.Background())
	s := &Session{module: mod, ctx: life, cancel: cancel, functions: make(map[string]api.Function)}
	fail := func(e error) (*Session, error) { s.Close(); return nil, e }
	expected := map[string]int{"abi_version": 0, "catalog_ptr": 0, "catalog_len": 0, "session_size": 0, "session_init": 1, "describe": 2, "object_create": 6, "object_open": 2, "object_release": 2, "dial_target": 4, "handshake": 4, "write_limit": 3, "transform": 5}
	for name, n := range expected {
		f := mod.ExportedFunction(name)
		if f == nil {
			return fail(fmt.Errorf("missing ABI export %s", name))
		}
		d := f.Definition()
		if len(d.ParamTypes()) != n || len(d.ResultTypes()) != 1 || d.ResultTypes()[0] != api.ValueTypeI32 {
			return fail(fmt.Errorf("invalid ABI signature %s", name))
		}
		for _, t := range d.ParamTypes() {
			if t != api.ValueTypeI32 {
				return fail(fmt.Errorf("invalid ABI parameter %s", name))
			}
		}
		s.functions[name] = f
	}
	v, err := s.call("abi_version")
	if err != nil || v != 1 {
		return fail(errors.New("unsupported Wasm ABI"))
	}
	size, err := s.call("session_size")
	if err != nil || size == 0 || size > 1<<20 {
		return fail(errors.New("invalid session arena size"))
	}
	mem := mod.Memory()
	if mem == nil {
		return fail(errors.New("missing exported memory"))
	}
	pages := (size + BufferSize + 65535) / 65536
	old, ok := mem.Grow(pages)
	if !ok {
		return fail(errors.New("cannot allocate session memory"))
	}
	s.arena = old * 65536
	s.scratch = s.arena + size
	if _, err = s.call("session_init", uint64(s.arena)); err != nil {
		return fail(err)
	}
	m.sessions = append(m.sessions, s)
	return s, nil
}

// call is only used while mu is held, or while the instance is being constructed.
func (s *Session) call(name string, args ...uint64) (uint32, error) {
	if s.ctx.Err() != nil {
		return 0, errors.New("wasm session closed")
	}
	// A conservative spike fuse, including interpreter + race instrumentation
	// on low-power hardware. Production needs workload-specific scheduling limits.
	ctx, cancel := context.WithTimeout(s.ctx, 2*time.Second)
	defer cancel()
	r, err := s.functions[name].Call(ctx, args...)
	s.calls++
	if err != nil {
		s.cancel()
		return 0, fmt.Errorf("wasm %s: %w", name, err)
	}
	return uint32(r[0]), nil
}
func (s *Session) Close() error {
	s.cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.module.Close(context.Background())
}
func (s *Session) Calls() uint64 { s.mu.Lock(); defer s.mu.Unlock(); return s.calls }
func (s *Session) Catalog() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, e := s.call("catalog_ptr")
	if e != nil {
		return "", e
	}
	n, e := s.call("catalog_len")
	if e != nil {
		return "", e
	}
	if n > 4096 {
		return "", errors.New("catalog too large")
	}
	b, ok := s.module.Memory().Read(p, n)
	if !ok {
		return "", errors.New("invalid catalog")
	}
	return string(b), nil
}
func (s *Session) Profile(name string) (uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(name) > 256 {
		return 0, errors.New("constructor name too long")
	}
	s.module.Memory().Write(s.scratch, []byte(name))
	return s.call("describe", uint64(s.scratch), uint64(len(name)))
}
func (s *Session) create(name string, param uint32, relay string) (uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(name) > 256 || len(relay) > 255 {
		return 0, errors.New("constructor parameter too long")
	}
	s.module.Memory().Write(s.scratch, []byte(name))
	s.module.Memory().Write(s.scratch+256, []byte(relay))
	h, e := s.call("object_create", uint64(s.arena), uint64(s.scratch), uint64(len(name)), uint64(param), uint64(s.scratch+256), uint64(len(relay)))
	if e == nil && h == 0 {
		e = errors.New("constructor rejected parameters or object capacity exhausted")
	}
	return h, e
}
func (s *Session) open(h uint32) (uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, e := s.call("object_open", uint64(s.arena), uint64(h))
	if e == nil && v == 0 {
		e = errors.New("invalid/closed factory or object capacity exhausted")
	}
	return v, e
}
func (s *Session) release(h uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.call("object_release", uint64(s.arena), uint64(h))
}
func (s *Session) bufferCall(name string, h uint32, buf []byte, extra ...uint64) (uint32, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(buf) > BufferSize {
		return 0, nil, errors.New("input too large")
	}
	if !s.module.Memory().Write(s.scratch, buf) {
		return 0, nil, errors.New("invalid scratch memory")
	}
	args := []uint64{uint64(s.arena), uint64(h)}
	args = append(args, extra...)
	args = append(args, uint64(s.scratch), uint64(len(buf)))
	v, e := s.call(name, args...)
	if e != nil {
		return 0, nil, e
	}
	if int32(v) < 0 {
		return 0, nil, fmt.Errorf("guest rejected %s", name)
	}
	n := v
	if name == "handshake" {
		n = v & 65535
	}
	if n > BufferSize {
		return 0, nil, errors.New("guest output too large")
	}
	b, ok := s.module.Memory().Read(s.scratch, n)
	if !ok {
		return 0, nil, errors.New("guest output out of bounds")
	}
	return v, append([]byte(nil), b...), nil
}
func (s *Session) transform(h uint32, encode bool, p []byte) ([]byte, error) {
	var dir uint64
	if encode {
		dir = 1
	}
	_, b, e := s.bufferCall("transform", h, p, dir)
	return b, e
}
func (s *Session) limit(h uint32, n int) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, e := s.call("write_limit", uint64(s.arena), uint64(h), uint64(n))
	if e == nil && (v == 0 || v > uint32(n)) {
		e = errors.New("invalid guest write limit")
	}
	return int(v), e
}
