package metrics

import (
	"bufio"
	"fmt"
	"git.openprivacy.ca/cwtch.im/tapir"
	"git.openprivacy.ca/openprivacy/log"
	"github.com/struCoder/pidusage"
	"os"
	"path"
	"sync"
	"time"
)

const (
	reportFile = "serverMonitorReport.txt"
)

// Monitors is a package of metrics for a Cwtch Server including message count, CPU, Mem, and conns
type Monitors struct {
	MessageCounter      Counter
	TotalMessageCounter Counter
	Messages            MonitorHistory
	CPU                 MonitorHistory
	Memory              MonitorHistory
	ClientConns         MonitorHistory
	starttime           time.Time
	breakChannel        chan bool
	log                 bool
	configDir           string
}

// Start initializes a Monitors's monitors
func (mp *Monitors) Start(ts tapir.Service, configDir string, log bool) {
	mp.log = log
	mp.configDir = configDir
	mp.starttime = time.Now()
	mp.breakChannel = make(chan bool)
	mp.MessageCounter = NewCounter()

	// Maintain a count of total messages
	mp.TotalMessageCounter = NewCounter()
	mp.Messages = NewMonitorHistory(Count, Cumulative, func() (c float64) {
		c = float64(mp.MessageCounter.Count())
		mp.TotalMessageCounter.Add(int(c))
		mp.MessageCounter.Reset()
		return
	})

	var pidUsageLock sync.Mutex
	mp.CPU = NewMonitorHistory(Percent, Average, func() float64 {
		pidUsageLock.Lock()
		defer pidUsageLock.Unlock()
		sysInfo, _ := pidusage.GetStat(os.Getpid())
		return float64(sysInfo.CPU)
	})
	mp.Memory = NewMonitorHistory(MegaBytes, Average, func() float64 {
		pidUsageLock.Lock()
		defer pidUsageLock.Unlock()
		sysInfo, _ := pidusage.GetStat(os.Getpid())
		return float64(sysInfo.Memory)
	})

	// TODO: replace with ts.
	mp.ClientConns = NewMonitorHistory(Count, Average, func() float64 { return float64(ts.Metrics().ConnectionCount) })

	if mp.log {
		go mp.run()
	}
}

func (mp *Monitors) run() {
	for {
		select {
		case <-time.After(time.Minute):
			mp.report()
		case <-mp.breakChannel:
			return
		}
	}
}

func (mp *Monitors) report() {
	f, err := os.Create(path.Join(mp.configDir, reportFile))
	if err != nil {
		log.Errorf("Could not open monitor reporting file: %v", err)
		return
	}
	defer f.Close()

	w := bufio.NewWriter(f)

	fmt.Fprintf(w, "Uptime: %v\n\n", time.Now().Sub(mp.starttime))

	fmt.Fprintln(w, "messages:")
	mp.Messages.Report(w)

	fmt.Fprintln(w, "\nClient Connections:")
	mp.ClientConns.Report(w)

	fmt.Fprintln(w, "\nCPU:")
	mp.CPU.Report(w)

	fmt.Fprintln(w, "\nMemory:")
	mp.Memory.Report(w)

	w.Flush()
}

// Stop stops all the monitors in a Monitors
func (mp *Monitors) Stop() {
	if mp.log {
		mp.breakChannel <- true
	}
	mp.Messages.Stop()
	mp.CPU.Stop()
	mp.Memory.Stop()
	mp.ClientConns.Stop()
}
