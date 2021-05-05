// Copyright (c) 2021 BitMaelum Authors
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package internal

import (
	"fmt"
	"time"
)

type ctxKey int

const (
	// CtxSpinnerContext is a context key
	CtxSpinnerContext ctxKey = iota
)

// Spinner is a structure that will display a nice spinning char to inform that the system is busy with something
type Spinner struct {
	d       time.Duration
	ch      chan int
	charset []string
	idx     int
}

var (
	charset = []string{"⠁", "⠁", "⠉", "⠙", "⠚", "⠒", "⠂", "⠂", "⠒", "⠲", "⠴", "⠤", "⠄", "⠄", "⠤", "⠠", "⠠", "⠤", "⠦", "⠖", "⠒", "⠐", "⠐", "⠒", "⠓", "⠋", "⠉", "⠈", "⠈"}
)

// NewSpinner will create a new spinner that spins on duration
func NewSpinner(d time.Duration) Spinner {
	return Spinner{
		d:       d,
		ch:      make(chan int),
		charset: charset,
	}
}

// Start will start the spinner
func (s *Spinner) Start() {
	go func() {
		for {
			select {
			case <-s.ch:
				return
			default:
				time.Sleep(s.d)
				fmt.Printf("%s\b", s.charset[s.idx])
				s.idx = (s.idx + 1) % len(s.charset)
			}
		}
	}()
}

// Stop will stop the spinner
func (s *Spinner) Stop() {
	s.ch <- 1
}
