/*
Copyright 2022 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package srv

import (
	"context"
	"crypto/rand"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCTRLCPassthrough(t *testing.T) {
	t.Parallel()

	m := NewTermManager()
	m.On()
	r, w := io.Pipe()
	m.AddReader("foo", r)
	go w.Write([]byte("\x03"))
	buf := make([]byte, 1)
	_, err := m.Read(buf)
	require.NoError(t, err)
	require.Equal(t, []byte("\x03"), buf)
}

func TestCTRLCCapture(t *testing.T) {
	t.Parallel()

	m := NewTermManager()
	r, w := io.Pipe()
	m.AddReader("foo", r)
	w.Write([]byte("\x03"))

	select {
	case <-m.TerminateNotifier():
	case <-time.After(time.Second * 10):
		t.Fatal("terminateNotifier should've seen an event")
	}
}

func TestHistoryKept(t *testing.T) {
	t.Parallel()

	m := NewTermManager()
	m.On()

	data := make([]byte, 10000)
	n, err := rand.Read(data)
	require.NoError(t, err)
	require.Equal(t, len(data), n)

	n, err = m.Write(data[:len(data)/2])
	require.NoError(t, err)
	require.Equal(t, len(data)/2, n)

	n, err = m.Write(data[len(data)/2:])
	require.NoError(t, err)
	require.Equal(t, len(data)/2, n)

	kept := data[len(data)-maxHistoryBytes:]
	require.Equal(t, m.GetRecentHistory(), kept)
}

func TestBufferedKept(t *testing.T) {
	t.Parallel()

	m := NewTermManager()

	data := make([]byte, 20000)
	n, err := rand.Read(data)
	require.NoError(t, err)
	require.Equal(t, len(data), n)

	n, err = m.Write(data)
	require.NoError(t, err)
	require.Equal(t, len(data), n)

	kept := data[len(data)-maxPausedHistoryBytes:]
	require.Equal(t, m.buffer, kept)
}

func TestNoReadWhenOff(t *testing.T) {
	t.Parallel()

	m := NewTermManager()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()

	r, w := io.Pipe()
	data := make([]byte, 90)
	n, err := rand.Read(data)
	require.NoError(t, err)

	discarded := make(chan struct{})
	m.onDiscard = func() { close(discarded) }

	// add our data source to the multiplexer
	m.AddReader("reader", r)

	// write some data into our pipe, making it available to the multiplexer
	_, err = w.Write(data[:n])
	require.NoError(t, err)

	// wait for the multiplexer to read the data, it should be discarded which will close the discard channel
	// and continue execution
	select {
	case <-discarded:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	// enable the multiplexer, data should now flow through instead of being dropped
	m.On()

	// write 3 more bytes, these should be buffered until a reader picks them up
	_, err = w.Write([]byte{1, 2, 3})
	require.NoError(t, err)

	// attempt to read the buffered data, this should succeed since the multiplexer should now allow dataflow
	n, err = m.Read(data)
	require.NoError(t, err)
	require.Equal(t, []byte{1, 2, 3}, data[:n])
}

// wrappedTermManagerReader wraps a TermManager and alerts
// that a Read is attempted via the reading chanel
type wrappedTermManagerReader struct {
	m       *TermManager
	reading chan struct{}
}

func (r *wrappedTermManagerReader) Read(p []byte) (int, error) {
	r.reading <- struct{}{}
	return r.m.Read(p)
}

func TestTermManagerRead(t *testing.T) {
	t.Parallel()

	data := []byte{1, 2, 3}
	const timeout = 10 * time.Second

	cases := []struct {
		name          string
		reader        func() io.Reader
		dataAssertion require.ValueAssertionFunc
		nAssertion    require.ValueAssertionFunc
		errAssertion  require.ErrorAssertionFunc
	}{
		{
			name: "data flow on and data to read",
			reader: func() io.Reader {
				m := NewTermManager()
				m.On()
				m.remaining = data

				return m
			},
			dataAssertion: func(t require.TestingT, i interface{}, i2 ...interface{}) {
				require.Equal(t, i, data, i2...)
			},
			nAssertion: func(t require.TestingT, i interface{}, i2 ...interface{}) {
				require.Equal(t, i, len(data), i2...)
			},
			errAssertion: require.NoError,
		},
		{
			name: "data flow on and data to read but closed",
			reader: func() io.Reader {
				m := NewTermManager()
				m.On()
				m.remaining = data
				m.Close()

				return m
			},
			dataAssertion: require.Empty,
			nAssertion: func(t require.TestingT, i interface{}, i2 ...interface{}) {
				require.Equal(t, i, 0, i2...)
			},
			errAssertion: func(t require.TestingT, err error, i ...interface{}) {
				require.ErrorIs(t, err, io.EOF, i...)
			},
		},
		{
			name: "closed while waiting",
			reader: func() io.Reader {
				m := NewTermManager()
				m.Off()

				r := &wrappedTermManagerReader{
					m:       m,
					reading: make(chan struct{}, 1),
				}

				go func() {
					// wait until read occurs
					select {
					case <-r.reading:
					case <-time.After(timeout):
						m.Close()
						return
					}

					// transition between on and off a few times
					for i := 0; i < 5; i++ {
						if i%2 == 0 {
							m.Off()
						} else {
							m.On()
						}
					}

					// close the reader and return
					m.Close()
				}()

				return r
			},
			dataAssertion: require.Empty,
			nAssertion:    require.Zero,
			errAssertion: func(t require.TestingT, err error, i ...interface{}) {
				require.ErrorIs(t, err, io.EOF, i...)
			},
		},
		{
			name: "data flow changes to on while waiting with existing data to read",
			reader: func() io.Reader {
				m := NewTermManager()
				m.Off()
				m.remaining = data

				r := &wrappedTermManagerReader{
					m:       m,
					reading: make(chan struct{}, 1),
				}

				go func() {
					// wait until read occurs
					select {
					case <-r.reading:
					case <-time.After(timeout):
						m.Close()
						return
					}

					// transition between on and off a few times
					for i := 0; i <= 5; i++ {
						if i < 5 {
							m.Off()
						} else {
							m.On()
						}
					}
				}()

				return r
			},
			dataAssertion: func(t require.TestingT, i interface{}, i2 ...interface{}) {
				require.Equal(t, i, data, i2...)
			},
			nAssertion: func(t require.TestingT, i interface{}, i2 ...interface{}) {
				require.Equal(t, i, len(data), i2...)
			},
			errAssertion: require.NoError,
		},
		{
			name: "data flow is on but waits for data to read",
			reader: func() io.Reader {
				m := NewTermManager()
				m.On()

				r := &wrappedTermManagerReader{
					m:       m,
					reading: make(chan struct{}, 1),
				}

				go func() {
					// wait until read occurs
					select {
					case <-r.reading:
					case <-time.After(timeout):
						m.Close()
						return
					}

					// transition between on and off a few times
					for i := 0; i < 5; i++ {
						if i%2 == 0 {
							m.Off()
						} else {
							m.On()
						}
					}

					// explicitly set on
					m.On()

					// send empty data first
					m.incoming <- []byte{}

					// send actual data that should be read
					m.incoming <- data
				}()

				return r
			},
			dataAssertion: func(t require.TestingT, i interface{}, i2 ...interface{}) {
				require.Equal(t, i, data, i2...)
			},
			nAssertion: func(t require.TestingT, i interface{}, i2 ...interface{}) {
				require.Equal(t, i, len(data), i2...)
			},
			errAssertion: require.NoError,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.reader()
			d := make([]byte, 100)
			n, err := r.Read(d)
			tt.errAssertion(t, err)
			tt.nAssertion(t, n)
			tt.dataAssertion(t, d[:n])
		})
	}

}
