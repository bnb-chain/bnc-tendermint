// Package gopool contains tools for goroutine reuse.
package gopool

import (
	"fmt"
	"runtime/debug"
	"time"

	"github.com/tendermint/tendermint/libs/common"
)

// ErrScheduleTimeout returned by Pool to indicate that there no free
// goroutines during some period of time.
var ErrScheduleTimeout = fmt.Errorf("schedule error: timed out")

// Pool contains logic of goroutine reuse.
type Pool struct {
	common.BaseService
	spawn     int
	sem       chan struct{}
	taskQueue chan func()
}

// NewPool creates new goroutine pool with given size. It also creates a taskQueue
// of given size.
func NewPool(size, queue, spawn int) *Pool {
	if spawn <= 0 && queue > 0 {
		panic("dead queue configuration detected")
	}
	if spawn > size {
		panic("spawn > workers")
	}
	p := &Pool{
		sem:       make(chan struct{}, size),
		taskQueue: make(chan func(), queue),
		spawn:     spawn,
	}
	p.BaseService = *common.NewBaseService(nil, "routine-pool", p)

	return p
}

func (p *Pool) QueuedTasks() int {
	return len(p.taskQueue)
}

// Spawns given amount of goroutines.
func (p *Pool) OnStart() error {
	for i := 0; i < p.spawn; i++ {
		p.sem <- struct{}{}
		go p.worker(func() {})
	}
	return nil
}

// Schedule schedules task to be executed over pool's workers.
func (p *Pool) Schedule(task func()) {
	p.schedule(task, nil)
}

// ScheduleTimeout schedules task to be executed over pool's workers.
// It returns ErrScheduleTimeout when no free workers met during given timeout.
func (p *Pool) ScheduleTimeout(timeout time.Duration, task func()) error {
	return p.schedule(task, time.After(timeout))
}

func (p *Pool) schedule(task func(), timeout <-chan time.Time) error {
	select {
	case <-timeout:
		return ErrScheduleTimeout
	case p.taskQueue <- task:
		return nil
	case p.sem <- struct{}{}:
		go p.worker(task)
		return nil
	}
}

func (p *Pool) worker(task func()) {
	defer func() {
		if r := recover(); r != nil {
			p.Logger.Error("failed to process task", "err", r, "stack", string(debug.Stack()))

			//Only create new routine while panic
			<-p.sem
		}
	}()

	task()
	for {
		select {
		case <-p.Quit():
			return
		case t := <-p.taskQueue:
			t()
		}
	}
}
