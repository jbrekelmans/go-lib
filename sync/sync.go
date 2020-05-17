package sync

import (
	"context"
	"fmt"
	"sync"
)

// PanicError is an error that can be returned from functions to communicate a recoverable panic occured on another Goroutine.
type PanicError struct {
	Data interface{}
}

func (p *PanicError) Error() string {
	return fmt.Sprintf("a Goroutine panicked: %v", p.Data)
}

// CallInParallelReturnWhenAnyError calls each function on its own Goroutine and returns the first error, if any.
// More specifically, when a function:
// 1. returns an error; -or
// 2. panics and the panic is recoverable;
// ...then the context passed to all other functions is canceled and:
// 1. the error is returned; -or
// 2. the panic is returned as a *PanicError;
// respectively.
// If none of the above conditions occur (no function returns an error and all functions that panic are unrecoverable panics)
// then nil is returned.
func CallInParallelReturnWhenAnyError(ctx context.Context, funcSlice ...func(ctx context.Context) error) error {
	ctxCancelable, cancelFunc := context.WithCancel(ctx)
	var waitGroup sync.WaitGroup
	var mutex sync.Mutex
	var errFirst error
	for i := 0; i < len(funcSlice); i++ {
		f := funcSlice[i]
		waitGroup.Add(1)
		go func() {
			canRecover := true
			defer func() {
				waitGroup.Done()
				if canRecover {
					err2 := &PanicError{
						Data: recover(),
					}
					mutex.Lock()
					defer mutex.Unlock()
					if errFirst == nil {
						errFirst = err2
						cancelFunc()
					}
				}
			}()
			err2 := f(ctxCancelable)
			if err2 == nil {
				return
			}
			canRecover = false
			mutex.Lock()
			defer mutex.Unlock()
			if errFirst == nil {
				errFirst = err2
				cancelFunc()
			}
		}()
	}
	waitGroup.Wait()

	// This call is not necessary since cancelFunc is always called (unless this Goroutine panics somehow),
	// but allows static code analysis to prove the context is cancelled.
	cancelFunc()
	return errFirst
}
