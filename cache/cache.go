package cache

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	jaspersync "github.com/jbrekelmans/go-lib/sync"
)

// CachedEvaluator is a cache for an evaluator (a function) such that the evaluator is expensive enough to justify ensuring that only
// one Goroutine should be running the evaluator at any one time (and other Goroutines will wait as needed).
// A CachedEvaluator should be wrapped for type-safety.
// See NewCachedEvaluator.
type CachedEvaluator interface {
	GetCacheOnly() (value interface{})

	// err can be a *"github.com/jbrekelmans/go-lib/sync".PanicError in circumstances where the Goroutine computing the value panics and the panic is recoverable.
	Get(ctx context.Context) (value interface{}, err error)

	// Evaluate is the same as Get, except:
	// Evaluate always ensures a Goroutine is evaluating. If there are no Goroutines evaluating then
	// evaluator is called.
	Evaluate(ctx context.Context) (value interface{}, err error)
}

type cachedEvaluator struct {
	evaluator func(ctx context.Context) (interface{}, error)
	mutex     sync.Mutex
	value     atomic.Value
	operation *operation
}

// operation represents an ongoing evaluation and stores informaton related to Goroutines
// interested in the evaluation.
//
// refs is a counter for the number of Goroutines inside a Get that are waiting for the evaluation.
// When the counter reaches 0 the context of the evaluation is canceled. This is needed to avoid the
// following scenario in a more naive implementation:
// 1. Goroutine X starts a call to Get with context CX that causes a call to factory (because no value is cached). CX is passed
// to the evaluator.
// 2. Goroutine Y (X != Y) calls Get with context CY (CY != CX) and starts waiting for the evaluation. Goroutine Y never cancels CY.
// 3. CX is canceled and the evaluation returns an error because CX is done.
// 4. Since the evaluation completed, Goroutine Y returns the error.
// This is not optimal because the evaluation did not have to be canceled, because Goroutine Y was waiting for it.
//
// value and err are set to the return values of the call to factory.
// waitChannel is closed after value and err are set.
type operation struct {
	cancelFunc  context.CancelFunc
	err         error
	refs        int64
	value       interface{}
	waitChannel <-chan struct{}
}

func (o *operation) addRef() {
	atomic.AddInt64(&o.refs, 1)
}

func (o *operation) removeRef() {
	if atomic.AddInt64(&o.refs, -1) == 0 {
		o.cancelFunc()
	}
}

// NewCachedEvaluator returns a cache for calls to evaluator, as defined by CachedEvaluator.
func NewCachedEvaluator(evaluator func(ctx context.Context) (value interface{}, err error)) (CachedEvaluator, error) {
	if evaluator == nil {
		return nil, fmt.Errorf("evaluator must not be nil")
	}
	return &cachedEvaluator{
		evaluator: evaluator,
	}, nil
}

func (c *cachedEvaluator) GetCacheOnly() (value interface{}) {
	return c.value.Load()
}

func (c *cachedEvaluator) evaluateLockedSection() *operation {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.operation != nil {
		return c.operation
	}
	waitChannel := make(chan struct{})
	o := &operation{
		waitChannel: waitChannel,
	}
	var ctx context.Context
	ctx, o.cancelFunc = context.WithCancel(context.Background())
	go func() {
		canRecover := true
		defer func() {
			if canRecover {
				// If we get here then a call to factory panicked
				data := recover()
				o.err = &jaspersync.PanicError{
					Data: data,
				}
				close(waitChannel)
				c.mutex.Lock()
				defer c.mutex.Unlock()
				c.operation = nil
			}
		}()
		o.value, o.err = c.evaluator(ctx)
		canRecover = false
		close(waitChannel)
		c.mutex.Lock()
		defer c.mutex.Unlock()
		c.operation = nil
		c.value.Store(o.value)
	}()
	c.operation = o
	return o
}

func (c *cachedEvaluator) Get(ctx context.Context) (value interface{}, err error) {
	value = c.value.Load()
	if value != nil {
		return
	}
	return c.Evaluate(ctx)
}

func (c *cachedEvaluator) Evaluate(ctx context.Context) (value interface{}, err error) {
	o := c.evaluateLockedSection()
	o.addRef()
	defer func() {
		o.removeRef()
	}()
	select {
	case <-ctx.Done():
		value = nil
		err = ctx.Err()
		return
	case <-o.waitChannel:
		value, err = o.value, o.err
		return
	}
}
