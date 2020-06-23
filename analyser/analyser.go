package analyser

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	_ "log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)



type StatsForSpecificDecoy struct {
	numSuccesses int
	numFailures int
	failureRate float64
}

type AggregatedCountryStats struct {
	decoyStatsForThisCountry map[string]*StatsForSpecificDecoy // decoy ip -> stats
	averageFailureRate float64
}

type Connection struct {
	connectionType string
	clientIP string
	decoyIP string
	clientCountry string
}

type Analyser struct {
	countryStats      map[string]*AggregatedCountryStats // Country name -> stats
	decoyStats        map[string]*StatsForSpecificDecoy // Decoy ip -> stats
	ipToHostname      map[string]string
	countryChannel    chan Connection
	decoyChannel      chan Connection
	completeDecoyList []string
	mainDir           string
	FatalError        bool
}


func InitAnalyser() *Analyser{
	al := new(Analyser)
	al.countryStats = make(map[string]*AggregatedCountryStats)
	al.decoyStats = make(map[string]*StatsForSpecificDecoy)
	al.ipToHostname = make(map[string]string)
	al.countryChannel = make(chan Connection, 64)
	al.decoyChannel = make(chan Connection, 64)
	_, currentDir, _ := execShell("pwd")
	currentDir = currentDir[:len(currentDir) - 1] + "/"
	al.mainDir = currentDir
	return al
}

const ShellToUse = "bash"

func (al *Analyser) checkForError(err error, stderr string) bool {
	if err != nil {
		println(err.Error())
		al.FatalError = true
	}
	if stderr != "" {
		println(stderr)
		al.FatalError = true
	}
	if al.FatalError == true {
		return true
	} else {
		return false
	}
}

func execShell(command string) (error, string, string) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	cmd := exec.Command(ShellToUse, "-c", command)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return err, stdout.String(), stderr.String()
}

func directoryChanged() {
	err, stdout, stderr := execShell("pwd")
	if err == nil && stderr == "" {
		fmt.Printf("	@@@Directory has been changed to %v", stdout)
	}
}

func (al *Analyser) cd(dir string) {
	err := os.Chdir(dir)
	if !al.checkForError(err, "") {
		directoryChanged()
	}
}

func (al *Analyser) ReadDecoyList() {
	al.cd(al.mainDir)
	println("Pulling decoy-lists from github ...")
	err, stdout, stderr := execShell("git clone git@github.com:refraction-networking/decoy-lists.git")
	if !al.checkForError(err, "") {
		al.cd("decoy-lists")
		_, stdout, _ = execShell("ls")
		files := strings.Split(stdout, "\n")
		fileNameOfLatestDecoyList := ""

		for i := len(files) - 1; i >= 0; i-- {
			if strings.HasSuffix(files[i], "-decoys.txt") {
				fileNameOfLatestDecoyList = files[i]
				break
			}
		}

		fmt.Printf("Reading %v ...\n", fileNameOfLatestDecoyList)
		f, err := os.Open(fileNameOfLatestDecoyList)
		defer f.Close()
		if err != nil {
			println(err.Error())
		}
		scanner := bufio.NewScanner(f)
		scanner.Scan()

		for {
			scanner.Scan()
			al.completeDecoyList = append(al.completeDecoyList, scanner.Text())
			row := strings.Split(scanner.Text(), string(','))
			if scanner.Text() == "" {
				break
			} else {
				ip := row[0]
				hostname := row[1]
				al.ipToHostname[ip] = hostname
			}
		}
		al.completeDecoyList = al.completeDecoyList[:len(al.completeDecoyList)-1] //empty line at the end
		al.cd(al.mainDir)
		println("Cleaning up decoy-lists ...")
		err, stdout, stderr = execShell("rm -rf decoy-lists")
		if err != nil || stderr != "" {
			println(stderr)
			if err != nil {
				println(err.Error())
			}
		}
	}
}

func (al *Analyser) FetchLog() {
	if al.FatalError == true {
		return
	}
	al.cd(al.mainDir)
	yesterdayDate := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	targetFileName := "tapdance-" + yesterdayDate + ".log.gz"
	SCPCommand := "sshpass scp -r yxluo@128.138.97.190:/var/log/logstash/refraction/tapdance/"
	SCPCommand += targetFileName
	SCPCommand += " "
	SCPCommand += al.mainDir
	fmt.Printf("Retrieving %v from Greed ...\n", targetFileName)
	err, _, stderr := execShell(SCPCommand)
	if !al.checkForError(err, stderr) {
		fmt.Printf("Decompressing %v ...\n", targetFileName)
		err, _, stderr = execShell("gunzip " + targetFileName)
		al.checkForError(err, stderr)
	}
}

func (al *Analyser) ReadLog() {
	if al.FatalError == true {
		return
	}
	al.cd(al.mainDir)
	yesterdayDate := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	targetFileName := "tapdance-" + yesterdayDate + ".log"
	fmt.Printf("Parsing %v ...\n", targetFileName)

	file, err := os.Open(targetFileName)
	if !al.checkForError(err, "") {
		decoder := json.NewDecoder(file)
		go func() {
			for true {
				v := new(map[string]interface{})
				err := decoder.Decode(v)
				if err != nil {
					break
				} else {
					go al.ProcessMessage(v)
				}
			}

			fmt.Printf("Finished parsing %v, closing channels ...\n", targetFileName)
			time.Sleep(10 * time.Second)
			close(al.countryChannel)
			close(al.decoyChannel)
			fmt.Printf("Removing %v ...\n", targetFileName)
			al.cd(al.mainDir)
			_, _, _ = execShell("rm -rf " + targetFileName)
		} ()
	}
}

func (al * Analyser) ProcessDecoyChannel(terminationChannel1 chan bool) {
	for connection := range al.decoyChannel {
		if _, exist := al.decoyStats[connection.decoyIP]; !exist {
			al.decoyStats[connection.decoyIP] = new(StatsForSpecificDecoy)
		}
		if connection.connectionType == "newflow" {
			al.decoyStats[connection.decoyIP].numSuccesses++
		} else {
			al.decoyStats[connection.decoyIP].numFailures++
		}

	}
	fmt.Println("Decoy Channel closed")
	close(terminationChannel1)
}

func (al *Analyser) ProcessCountryChannel(terminationChannel2 chan bool) {
	for connection := range al.countryChannel {
		if _, exist := al.countryStats[connection.clientCountry]; !exist {
			al.countryStats[connection.clientCountry] = new(AggregatedCountryStats)
			al.countryStats[connection.clientCountry].decoyStatsForThisCountry = make(map[string]*StatsForSpecificDecoy)
		}

		if _, exist := al.countryStats[connection.clientCountry].decoyStatsForThisCountry[connection.decoyIP]; !exist {
			al.countryStats[connection.clientCountry].decoyStatsForThisCountry[connection.decoyIP] = new(StatsForSpecificDecoy)
		}

		if connection.connectionType == "newflow" {
			al.countryStats[connection.clientCountry].decoyStatsForThisCountry[connection.decoyIP].numSuccesses++
		} else {
			al.countryStats[connection.clientCountry].decoyStatsForThisCountry[connection.decoyIP].numFailures++
		}
	}
	fmt.Println("Country Channel closed")
	close(terminationChannel2)
}

func (al *Analyser) ProcessMessage(v *map[string]interface{}) {
	if _, exist := (*v)["system"]; exist {
		system := (*v)["system"].(map[string]interface{})
		if _, exist := system["syslog"]; exist {
			syslog := system["syslog"].(map[string]interface{})
			if _, exist := syslog["message"]; exist {
				message := syslog["message"].(string)
				connection := ProcessMessage(message)
				if connection.connectionType != "" {
					al.decoyChannel <- connection
					al.countryChannel <- connection
				}
			}
		}
	}
}


func (al *Analyser)ComputeFailureRateForCountry(terminationChannel chan bool) {
	println("Computing failure rate for each country ...")
	for _, statsForEachCountry := range al.countryStats {
		for _,statsForEachDecoy := range statsForEachCountry.decoyStatsForThisCountry {
			statsForEachDecoy.failureRate = float64(statsForEachDecoy.numFailures) / (float64(statsForEachDecoy.numFailures) + float64(statsForEachDecoy.numSuccesses))
		}
	}
	println("Finished computing failure rate for each country ...")
	close(terminationChannel)
}

func (al *Analyser) ComputeFailureRateForDecoy(terminationChannel chan bool) {
	println("Computing failure rate for each decoy ...")

	for _, statsForEachDecoy := range al.decoyStats {
		statsForEachDecoy.failureRate = float64(statsForEachDecoy.numFailures) / (float64(statsForEachDecoy.numFailures) + float64(statsForEachDecoy.numSuccesses))
	}
	println("Finished computing failure rate for each decoy ...")
	close(terminationChannel)
}

func ProcessMessage(message string) Connection {
	splitMessage := strings.Split(message, " ")
	var connection Connection

	if len(splitMessage) > (7 + 3) {
		if splitMessage[7] == "newflow" {
			connection.connectionType = "newflow"
			connection.clientIP = strings.Split(splitMessage[7 + 1], ":")[0]
			connection.decoyIP = strings.Split(splitMessage[7 + 3], ":")[0]
		} else if splitMessage[7] == "faileddecoy" {
			connection.connectionType = "faileddecoy"
			connection.clientIP = strings.Split(splitMessage[7 + 1], ":")[0]
			connection.decoyIP = strings.Split(splitMessage[7 + 3], ":")[0]
		}
	}

	if connection.clientIP != "" {
		connection.clientCountry = GetCountryByIp(connection.clientIP)
	}

	return connection
}

type CoolDown struct {
	daysRemaining int
	NextBenchDays int
}

func (al *Analyser) CalculateAverageFailureRateForEachCountry() {
	for countryName, countryInfo  := range al.countryStats {
		var cumulativeSuccesses int
		var cumulativeFailures int
		for _, statsForEachDecoy := range countryInfo.decoyStatsForThisCountry {
			cumulativeFailures += statsForEachDecoy.numFailures
			cumulativeSuccesses += statsForEachDecoy.numSuccesses
		}
		countryInfo.averageFailureRate = float64(cumulativeFailures)/float64(cumulativeFailures + cumulativeSuccesses)
		fmt.Printf("The average failure rate for %v in the past day is %v(from %v reports) \n", countryName, countryInfo.averageFailureRate, cumulativeFailures + cumulativeSuccesses)
	}

}

func (al *Analyser) UpdateActiveDecoyList() {
	if al.FatalError == true {
		return
	}
	/*
	Benching Criteria:
		Failure Rate > daily average for each country + 0.05
	 */

	const amnesty = 0.05
	al.cd(al.mainDir)
	al.cd("list")

	for countryCode, countryInfo := range al.countryStats {
		coolDownStats := make(map[string]CoolDown)
		benchedFile, err := os.Open("./" + countryCode + "_Benched.csv")
		if err == nil { // There exist benched decoys for this country
			fmt.Printf("Processing %v_Benched.csv ...", countryCode)
			scanner := bufio.NewScanner(benchedFile)
			for scanner.Scan() {
				line := strings.Split(scanner.Text(), ",")
				IP := line[0]
				daysRemaining, _ := strconv.Atoi(line[1])
				NextBenchDays, _ := strconv.Atoi(line[2])
				coolDownStats[IP] = CoolDown{daysRemaining: daysRemaining, NextBenchDays: NextBenchDays}
			}

			for key, value := range coolDownStats {
				if value.daysRemaining == 0 {
					value.NextBenchDays--
					if value.NextBenchDays <= 0 {
						delete(coolDownStats, key)
					}
				} else {
					value.daysRemaining--
				}
			}
			benchedFile.Close()
			_, _, _ = execShell("rm -f" + countryCode + "_Benched.csv")
		}



		// bench bad decoys
		for decoyIP, DecoyInfo := range countryInfo.decoyStatsForThisCountry {
			if DecoyInfo.failureRate > countryInfo.averageFailureRate + amnesty {
				if value, exist := coolDownStats[decoyIP]; exist {
					value.daysRemaining = value.NextBenchDays
					value.NextBenchDays *= 2
					coolDownStats[decoyIP] = value
				} else {
					coolDownStats[decoyIP] = CoolDown{
						daysRemaining: 1,
						NextBenchDays: 2,
					}
				}
			}
		}

		//write benching info to file
		if len(coolDownStats) != 0 {
			benchedFile, err = os.Create(countryCode + "_Benched.csv")
			if err != nil {
				println(err.Error())
			}
			benchWriter := bufio.NewWriter(benchedFile)
			for decoyIP, coolDownInfo := range coolDownStats {
				_, _ = fmt.Fprintf(benchWriter, "%v,%v,%v\n", decoyIP, coolDownInfo.daysRemaining, coolDownInfo.NextBenchDays)
			}
			_ = benchWriter.Flush()
			benchedFile.Close()
		}

		//write active decoys to file
		_, _, _ = execShell("rm -f" + countryCode + "_Active.txt")
		if len(coolDownStats) != 0 {
			activeFile, _ := os.Create(countryCode + "_Active.txt")
			activeWriter := bufio.NewWriter(activeFile)
			for _, item := range al.completeDecoyList {
				if _, exist := coolDownStats[strings.Split(item, ",")[0]]; !exist{
					_, _ = fmt.Fprintf(activeWriter, item+"\n")
				} else {
					if coolDownStats[strings.Split(item, ",")[0]].daysRemaining == 0 {
						_, _ = fmt.Fprintf(activeWriter, item+"\n")
					}
				}
			}
			_ = activeWriter.Flush()
			activeFile.Close()
			fmt.Printf("%v decoys benched(%v of all available decoys) for %v\n", len(coolDownStats), float64(len(coolDownStats))/float64(len(al.ipToHostname)), countryCode)
		}
	}

	// Now deal with previous benched decoys for countries not on al.countryStats
	err, stdout, stderr := execShell("ls | grep .csv")
	if err == nil && stderr == "" {
		benchFiles := strings.Split(stdout, "\n")
		for _, benchFileName := range benchFiles {
			countryCode := strings.Split(benchFileName, "_")[0]
			if _, exist := al.countryStats[countryCode]; !exist {
				coolDownStats := make(map[string]CoolDown)
				benchedFile, err := os.Open("./" + countryCode + "_Benched.csv")
				if err == nil { // There exist benched decoys for this country
					fmt.Printf("Processing %v_Benched.csv ...", countryCode)
					scanner := bufio.NewScanner(benchedFile)
					for scanner.Scan() {
						line := strings.Split(scanner.Text(), ",")
						IP := line[0]
						daysRemaining, _ := strconv.Atoi(line[1])
						NextBenchDays, _ := strconv.Atoi(line[2])
						coolDownStats[IP] = CoolDown{daysRemaining: daysRemaining, NextBenchDays: NextBenchDays}
					}

					for key, value := range coolDownStats {
						if value.daysRemaining == 0 {
							value.NextBenchDays--
							if value.NextBenchDays <= 0 {
								delete(coolDownStats, key)
							}
						} else {
							value.daysRemaining--
						}
					}
					benchedFile.Close()
					_, _, _ = execShell("rm -f" + countryCode + "_Benched.csv")
				}
			}
		}
	} else {
		println(stderr)
	}


	al.cd(al.mainDir)
	al.cd("protowrapper")
	_,_,_ = execShell("sh run.sh")
	al.cd(al.mainDir)
}






























