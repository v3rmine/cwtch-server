package metrics

import (
	"bufio"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type counter struct {
	startTime time.Time
	count     uint64
	total     uint64
}

// Counter providers a threadsafe counter to use for storing long running counts
type Counter interface {
	Add(unit int)
	Reset()

	Count() int
	GetStarttime() time.Time
}

// NewCounter initializes a counter starting at time.Now() and a count of 0 and returns it
func NewCounter() Counter {
	c := &counter{startTime: time.Now(), count: 0, total: 0}
	return c
}

// Add add a count of unit to the counter
func (c *counter) Add(unit int) {
	atomic.AddUint64(&c.count, uint64(unit))
}

// Count returns the count since Start
func (c *counter) Count() int {
	return int(atomic.LoadUint64(&c.count))
}

func (c *counter) Reset() {
	atomic.StoreUint64(&c.count, 0)
	c.startTime = time.Now()
}

// GetStarttime returns the starttime of the counter
func (c *counter) GetStarttime() time.Time {
	return c.startTime
}

// MonitorType controls how the monitor will report itself
type MonitorType int

const (
	// Count indicates the monitor should report in interger format
	Count MonitorType = iota
	// Percent indicates the monitor should report in decimal format with 2 places
	Percent
	// MegaBytes indicates the monitor should transform the raw number into MBs
	MegaBytes
)

// MonitorAccumulation controls how monitor data is accumulated over time into larger summary buckets
type MonitorAccumulation int

const (
	// Cumulative values with sum over time
	Cumulative MonitorAccumulation = iota
	// Average values will average over time
	Average
)

type monitorHistory struct {
	monitorType         MonitorType
	monitorAccumulation MonitorAccumulation

	starttime           time.Time
	perMinutePerHour    [60]float64
	timeLastHourRotate  time.Time
	perHourForDay       [24]float64
	timeLastDayRotate   time.Time
	perDayForWeek       [7]float64
	timeLastWeekRotate  time.Time
	perWeekForMonth     [4]float64
	timeLastMonthRotate time.Time
	perMonthForYear     [12]float64

	monitor func() float64

	breakChannel chan bool
	lock         sync.Mutex
}

// MonitorHistory runs a monitor every minute and rotates and averages the results out across time
type MonitorHistory interface {
	Start()
	Stop()

	Minutes() []float64
	Hours() []float64
	Days() []float64
	Weeks() []float64
	Months() []float64

	Report(w *bufio.Writer)
}

// NewMonitorHistory returns a new MonitorHistory with starttime of time.Now and Started running with supplied monitor
func NewMonitorHistory(t MonitorType, a MonitorAccumulation, monitor func() float64) MonitorHistory {
	mh := &monitorHistory{monitorType: t, monitorAccumulation: a, starttime: time.Now(), monitor: monitor, breakChannel: make(chan bool),
		timeLastHourRotate: time.Now(), timeLastDayRotate: time.Now(), timeLastWeekRotate: time.Now(),
		timeLastMonthRotate: time.Now()}
	mh.Start()
	return mh
}

// Start starts a monitorHistory go rountine to run the monitor at intervals and rotate history
func (mh *monitorHistory) Start() {
	go mh.monitorThread()
}

// Stop stops a monitorHistory go routine
func (mh *monitorHistory) Stop() {
	mh.breakChannel <- true
}

// Minutes returns the last 60 minute monitoring results
func (mh *monitorHistory) Minutes() []float64 {
	return mh.returnCopy(mh.perMinutePerHour[:])
}

// Hours returns the last 24 hourly averages of monitor results
func (mh *monitorHistory) Hours() []float64 {
	return mh.returnCopy(mh.perHourForDay[:])
}

// Days returns the last 7 day averages of monitor results
func (mh *monitorHistory) Days() []float64 {
	return mh.returnCopy(mh.perDayForWeek[:])
}

// Weeks returns the last 4 weeks of averages of monitor results
func (mh *monitorHistory) Weeks() []float64 {
	return mh.returnCopy(mh.perWeekForMonth[:])
}

// Months returns the last 12 months of averages of monitor results
func (mh *monitorHistory) Months() []float64 {
	return mh.returnCopy(mh.perMonthForYear[:])
}

func (mh *monitorHistory) Report(w *bufio.Writer) {
	mh.lock.Lock()
	fmt.Fprintln(w, "Minutes:", reportLine(mh.monitorType, mh.perMinutePerHour[:]))
	fmt.Fprintln(w, "Hours:  ", reportLine(mh.monitorType, mh.perHourForDay[:]))
	fmt.Fprintln(w, "Days:   ", reportLine(mh.monitorType, mh.perDayForWeek[:]))
	fmt.Fprintln(w, "Weeks:  ", reportLine(mh.monitorType, mh.perWeekForMonth[:]))
	fmt.Fprintln(w, "Months: ", reportLine(mh.monitorType, mh.perMonthForYear[:]))
	mh.lock.Unlock()
}

func reportLine(t MonitorType, array []float64) string {
	switch t {
	case Count:
		return strings.Trim(strings.Join(strings.Fields(fmt.Sprintf("%.0f", array)), " "), "[]")
	case Percent:
		return strings.Trim(strings.Join(strings.Fields(fmt.Sprintf("%.2f", array)), " "), "[]")
	case MegaBytes:
		mbs := make([]int, len(array))
		for i, b := range array {
			mbs[i] = int(b) / 1024 / 1024
		}
		return strings.Trim(strings.Join(strings.Fields(fmt.Sprintf("%d", mbs)), "MBs "), "[]") + "MBs"
	}
	return ""
}

func (mh *monitorHistory) returnCopy(slice []float64) []float64 {
	retSlice := make([]float64, len(slice))
	mh.lock.Lock()
	for i, v := range slice {
		retSlice[i] = v
	}
	mh.lock.Unlock()
	return retSlice
}

func rotateAndAccumulate(array []float64, newVal float64, acc MonitorAccumulation) float64 {
	total := float64(0.0)
	for i := len(array) - 1; i > 0; i-- {
		array[i] = array[i-1]
		total += array[i]
	}
	array[0] = newVal
	total += newVal
	if acc == Cumulative {
		return total
	}
	return total / float64(len(array))
}
func accumulate(array []float64, acc MonitorAccumulation) float64 {
	total := float64(0)
	for _, x := range array {
		total += x
	}
	if acc == Cumulative {
		return total
	}
	return total / float64(len(array))
}

// monitorThread is the goroutine in a monitorHistory that does per minute monitoring and rotation
func (mh *monitorHistory) monitorThread() {
	for {
		select {
		case <-time.After(time.Minute):
			mh.lock.Lock()

			minuteAvg := rotateAndAccumulate(mh.perMinutePerHour[:], mh.monitor(), mh.monitorAccumulation)

			if time.Now().Sub(mh.timeLastHourRotate) > time.Hour {
				rotateAndAccumulate(mh.perHourForDay[:], minuteAvg, mh.monitorAccumulation)
				mh.timeLastHourRotate = time.Now()
			}

			if time.Now().Sub(mh.timeLastDayRotate) > time.Hour*24 {
				rotateAndAccumulate(mh.perDayForWeek[:], accumulate(mh.perHourForDay[:], mh.monitorAccumulation), mh.monitorAccumulation)
				mh.timeLastDayRotate = time.Now()
			}

			if time.Now().Sub(mh.timeLastWeekRotate) > time.Hour*24*7 {
				rotateAndAccumulate(mh.perWeekForMonth[:], accumulate(mh.perDayForWeek[:], mh.monitorAccumulation), mh.monitorAccumulation)
				mh.timeLastWeekRotate = time.Now()
			}

			if time.Now().Sub(mh.timeLastMonthRotate) > time.Hour*24*7*4 {
				rotateAndAccumulate(mh.perMonthForYear[:], accumulate(mh.perWeekForMonth[:], mh.monitorAccumulation), mh.monitorAccumulation)
				mh.timeLastMonthRotate = time.Now()
			}

			mh.lock.Unlock()

		case <-mh.breakChannel:
			return
		}
	}
}
