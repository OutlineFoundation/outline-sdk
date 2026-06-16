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

package packetrelay

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// Make sure the underlying packet relay can be initialized and updated
func TestRelayCanBeUpdated(t *testing.T) {
	defRelay := &sessionCountPacketRelay{}
	newRelay := &sessionCountPacketRelay{}
	p, err := NewDelegatePacketRelay(defRelay)
	require.NotNil(t, p)
	require.NoError(t, err)

	// Initially no NewAssociation is called
	require.Exactly(t, 0, defRelay.Count())
	require.Exactly(t, 0, newRelay.Count())

	snd, rcv, err := p.NewAssociation()
	require.Nil(t, snd)
	require.Nil(t, rcv)
	require.NoError(t, err)

	// defRelay.NewAssociation's count++
	require.Exactly(t, 1, defRelay.Count())
	require.Exactly(t, 0, newRelay.Count())

	// SetRelay should not call NewAssociation
	p.SetRelay(newRelay)
	require.Exactly(t, 1, defRelay.Count())
	require.Exactly(t, 0, newRelay.Count())

	// newRelay.NewAssociation's count += 2
	snd, rcv, err = p.NewAssociation()
	require.Nil(t, snd)
	require.Nil(t, rcv)
	require.NoError(t, err)

	snd, rcv, err = p.NewAssociation()
	require.Nil(t, snd)
	require.Nil(t, rcv)
	require.NoError(t, err)

	require.Exactly(t, 1, defRelay.Count())
	require.Exactly(t, 2, newRelay.Count())
}

// Make sure multiple goroutines can call NewAssociation and SetRelay concurrently
// Need to run this test with `-race` flag
func TestSetRelayRaceCondition(t *testing.T) {
	const relaysCnt = 10
	const sessionCntPerRelay = 5

	var relays [relaysCnt]*sessionCountPacketRelay
	for i := 0; i < relaysCnt; i++ {
		relays[i] = &sessionCountPacketRelay{}
	}

	dr, err := NewDelegatePacketRelay(relays[0])
	require.NotNil(t, dr)
	require.NoError(t, err)

	setRelayTask := &sync.WaitGroup{}
	cancelSetRelay := &atomic.Bool{}
	setRelayTask.Add(1)
	go func() {
		for i := 0; !cancelSetRelay.Load(); i = (i + 1) % relaysCnt {
			dr.SetRelay(relays[i])
		}
		setRelayTask.Done()
	}()

	newAssociationTask := &sync.WaitGroup{}
	newAssociationTask.Add(1)
	go func() {
		for i := 0; i < relaysCnt*sessionCntPerRelay; i++ {
			dr.NewAssociation()
		}
		newAssociationTask.Done()
	}()

	newAssociationTask.Wait()
	cancelSetRelay.Store(true)
	setRelayTask.Wait()

	expectedTotal := relaysCnt * sessionCntPerRelay
	actualTotal := 0
	for i := 0; i < relaysCnt; i++ {
		require.GreaterOrEqual(t, relays[i].Count(), 0)
		actualTotal += relays[i].Count()
	}
	require.Equal(t, expectedTotal, actualTotal)
}

// Make sure we can SetRelay to nil, which makes NewAssociation fail with errNoRelay
func TestSetRelayWithNilValue(t *testing.T) {
	// initialization with nil does not return error, but calling NewAssociation will return errNoRelay
	dr, err := NewDelegatePacketRelay(nil)
	require.NoError(t, err)
	require.NotNil(t, dr)
	_, _, err = dr.NewAssociation()
	require.ErrorIs(t, err, errNoRelay)

	dr, err = NewDelegatePacketRelay(&sessionCountPacketRelay{})
	require.NoError(t, err)
	require.NotNil(t, dr)

	// SetRelay(nil) should not panic or error, but calling NewAssociation afterwards will return errNoRelay
	dr.SetRelay(nil)
	_, _, err = dr.NewAssociation()
	require.ErrorIs(t, err, errNoRelay)
}

// Make sure we can SetRelay to different types
func TestSetRelayOfDifferentTypes(t *testing.T) {
	defRelay := &sessionCountPacketRelay{}
	newRelay := &noopPacketRelay{}

	p, err := NewDelegatePacketRelay(defRelay)
	require.NotNil(t, p)
	require.NoError(t, err)

	// SetRelay should not return error
	p.SetRelay(newRelay)

	// NewAssociation should not go to defRelay
	snd, rcv, err := p.NewAssociation()
	require.Nil(t, snd)
	require.Nil(t, rcv)
	require.NoError(t, err)
	require.Exactly(t, 0, defRelay.Count())
}

// sessionCountPacketRelay logs the count of the NewAssociation calls, and returns nil interfaces
type sessionCountPacketRelay struct {
	cnt atomic.Int32
}

func (sp *sessionCountPacketRelay) NewAssociation() (PacketSender, PacketReceiver, error) {
	sp.cnt.Add(1)
	return nil, nil, nil
}

func (sp *sessionCountPacketRelay) Count() int {
	return int(sp.cnt.Load())
}

type noopPacketRelay struct{}

func (noopPacketRelay) NewAssociation() (PacketSender, PacketReceiver, error) {
	return nil, nil, nil
}
