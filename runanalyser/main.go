package main

import (
	"github.com/refraction-networking/dynamic-decoylist/analyser"
	"fmt"
	"time"
)
const IntervalPeriod time.Duration = 24 * time.Hour

const HourToTick int = 00
const MinuteToTick int = 05
const SecondToTick int = 00

type jobTicker struct {
	timer *time.Timer
}

func runningRoutine() {
	jobTicker := &jobTicker{}
	jobTicker.updateTimer()
	for {
		<-jobTicker.timer.C
		fmt.Println(time.Now(), "- just ticked")
		RunAnalysis()
		jobTicker.updateTimer()
	}
}

func (t *jobTicker) updateTimer() {
	nextTick := time.Date(time.Now().Year(), time.Now().Month(),
		time.Now().Day(), HourToTick, MinuteToTick, SecondToTick, 0, time.Local)
	if !nextTick.After(time.Now()) {
		nextTick = nextTick.Add(IntervalPeriod)
	}
	fmt.Println(nextTick, "- next tick")
	diff := nextTick.Sub(time.Now())
	if t.timer == nil {
		t.timer = time.NewTimer(diff)
	} else {
		t.timer.Reset(diff)
	}
}

func main() {
	RunAnalysis()
	for true {
		runningRoutine()
	}
}

func RunAnalysis() {
	var al *analyser.Analyser
	al = analyser.InitAnalyser()
	al.ReadDecoyList()
	al.FetchLog()
	al.ReadLog()

	terminationChannel1 := make(chan bool)
	terminationChannel2 := make(chan bool)
	go al.ProcessCountryChannel(terminationChannel2)
	go al.ProcessDecoyChannel(terminationChannel1)
	for _ = range terminationChannel1 {}
	for _ = range terminationChannel2 {}

	terminationChannel3 := make(chan bool)
	terminationChannel4 := make(chan bool)
	go al.ComputeFailureRateForCountry(terminationChannel3)
	go al.ComputeFailureRateForDecoy(terminationChannel4)
	for _ = range terminationChannel3 {}
	for _ = range terminationChannel4 {}

	al.CalculateAverageFailureRateForEachCountry()
	al.UpdateActiveDecoyList()
	al.LogCountryStats("IR")

	if al.FatalError {
		time.Sleep(10 * time.Minute)
		go RunAnalysis() // try again in 10 minutes if encounter error
	}
}
