package tools

import "sync"

// A simple atomic counter
type AtomicCounter struct {
	Lock  sync.Mutex
	Count int
}

func (counter *AtomicCounter) Increment() {
	counter.Lock.Lock()
	counter.Count++
	counter.Lock.Unlock()
}

func (counter *AtomicCounter) IncrementCustom(amount int) {
	counter.Lock.Lock()
	counter.Count += amount
	counter.Lock.Unlock()
}

func (counter *AtomicCounter) Read() int {
	counter.Lock.Lock()
	val := counter.Count
	counter.Lock.Unlock()

	return val
}

// A simple atomic flag
type AtomicFlag struct {
	Lock sync.Mutex
	Flag bool
}

func (flag *AtomicFlag) Toggle() {
	flag.Lock.Lock()
	flag.Flag = !flag.Flag
	flag.Lock.Unlock()
}

func (flag *AtomicFlag) Read() bool {
	flag.Lock.Lock()
	val := flag.Flag
	flag.Lock.Unlock()

	return val
}
