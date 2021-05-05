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

package stepper

import (
	"context"
	"fmt"
	"time"

	"github.com/bitmaelum/bitmaelum-suite/cmd/bm-client/internal"
)

// StepResult should be returned by RunFunc
type StepResult struct {
	Status   int    // Status to display
	Message  string // message to display after the run
	Continue bool   // Force continue on FAILED status
}

// Step is the basic step that can be added to a stepper
type Step struct {
	Title          string                      // Title of the step
	DisplaySpinner bool                        // Should we display a spinner on this step
	SkipIfFunc     func(s Stepper) bool        // Called to check if the step needs to be skipped
	RunFunc        func(s *Stepper) StepResult // Run function for this step
	CleanupFunc    func(s Stepper)             // Function to run for cleaning up after a failure

	Result *StepResult // The result of the step when finished
}

// Status constants
const (
	STOPPED = iota // Stepper is not running
	RUNNING        // Stepper is running
	FAILURE        // Stepper or step has failed
	SUCCESS        // Stepper or step has succeeded
	SKIPPED        // Step is skipped
	NOTICE         // Step throws a notification
	WARNING        // Step throws a warning
)

// Ansi constants
const (
	AnsiCr       = "\033[0G"
	AnsiClrEol   = "\033[K"
	AnsiFgRed    = "\033[1;31m"
	AnsiFgGreen  = "\033[1;32m"
	AnsiFgYellow = "\033[1;33m"
	AnsiFgBlue   = "\033[1;34m"
	AnsiFgCyan   = "\033[1;35m"
	AnsiReset    = "\033[0m"
)

// Stepper is the main stepping structure. You can add steps which will be executed
type Stepper struct {
	Steps   []Step
	StepIdx int
	Status  int
	Ctx     context.Context
}

// New will return a new empty stepper
func New() *Stepper {
	return &Stepper{
		Steps:   []Step{},
		StepIdx: 0,
		Status:  STOPPED,
		Ctx:     context.TODO(),
	}
}

// AddStep will add a new step to the stepper
func (s *Stepper) AddStep(step Step) {
	s.Steps = append(s.Steps, step)
}

// Run will execute all the steps in order
func (s *Stepper) Run() {
	s.Status = RUNNING

	failed := false

	for idx, step := range s.Steps {
		s.StepIdx = idx

		// Check if we need to do the step, or if we can skip it directly
		if step.SkipIfFunc != nil && step.SkipIfFunc(*s) {
			s.printSkip(step.Title)
			continue
		}

		result := s.runStep(step)

		if result.Status == FAILURE && !result.Continue {
			failed = true
			break
		}
	}

	if failed {
		s.Status = FAILURE
		s.cleanup()
		return
	}

	s.Status = SUCCESS
}

func (s *Stepper) runStep(step Step) StepResult {
	// Display running status line
	fmt.Printf("[       ] %s ", step.Title)

	// Display spinner if needed
	if step.DisplaySpinner {
		spinner := internal.NewSpinner(100 * time.Millisecond)
		fmt.Printf("\033[?25l")
		spinner.Start()

		defer func() {
			spinner.Stop()
			fmt.Printf("\033[?25h")
		}()
	}

	// Run the actual step function
	result := step.RunFunc(s)
	step.Result = &result

	// Display result
	msg := ""
	if result.Message != "" {
		msg = ": " + result.Message
	}
	switch result.Status {
	case SUCCESS:
		s.printSuccess(step.Title + msg)
	case FAILURE:
		s.printFailure(step.Title + msg)
	case NOTICE:
		s.printNotice(step.Title + msg)
	case WARNING:
		s.printWarning(step.Title + msg)
	case SKIPPED:
		s.printSkip(step.Title + msg)
	}

	return result
}

// Cleanup of the already ran steps
func (s *Stepper) cleanup() {
	for i := s.StepIdx; i >= 0; i-- {
		if s.Steps[i].CleanupFunc != nil {
			s.Steps[i].CleanupFunc(*s)
		}
	}
}

// printSuccess will print a success message
func (s *Stepper) printSuccess(msg string) {
	fmt.Printf("%s[%s%sSUCCESS%s] %s    \n", AnsiCr, AnsiClrEol, AnsiFgGreen, AnsiReset, msg)
}

// printFailure will print a failure message
func (s *Stepper) printFailure(msg string) {
	fmt.Printf("%s[%s%sFAILURE%s] %s    \n", AnsiCr, AnsiClrEol, AnsiFgRed, AnsiReset, msg)
}

// printWarning will print a warning message
func (s *Stepper) printWarning(msg string) {
	fmt.Printf("%s[%s%sWARNING%s] %s    \n", AnsiCr, AnsiClrEol, AnsiFgYellow, AnsiReset, msg)
}

// printNotice will print a notice message
func (s *Stepper) printNotice(msg string) {
	fmt.Printf("%s[%s%sNOTICE %s] %s    \n", AnsiCr, AnsiClrEol, AnsiFgBlue, AnsiReset, msg)
}

// printSkip will print a skipped message
func (s *Stepper) printSkip(msg string) {
	fmt.Printf("%s[%s%sSKIPPED%s] %s    \n", AnsiCr, AnsiClrEol, AnsiFgCyan, AnsiReset, msg)
}

// Failure ill return a failure step result
func (s *Stepper) Failure(msg string) StepResult {
	return StepResult{
		Status:  FAILURE,
		Message: msg,
	}
}

// Notice will return a notice step result
func (s *Stepper) Notice(msg string) StepResult {
	return StepResult{
		Status:  NOTICE,
		Message: msg,
	}
}

// Success will return a success step result
func (s *Stepper) Success(msg string) StepResult {
	return StepResult{
		Status:  SUCCESS,
		Message: msg,
	}
}
