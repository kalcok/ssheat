package ssheat

import (
	"os"
	"bufio"
	"fmt"
	"regexp"
	"github.com/fsnotify/fsnotify"
	"github.com/kalcok/jc"
	"time"
	"errors"
	"gopkg.in/mgo.v2/bson"
	"net/http"
	"io/ioutil"
	"encoding/json"
)
type (
	authAttempt struct {
		jc.Collection	`bson:"-"json:"-"`
		Ip string		`bson:"ip"json:"ip"`
		Host string		`bson:"host"json:"host"`
		Username string	`bson:"username"json:"username"`
		Date time.Time	`bson:"date"json:"date"`
		Country string	`bson:"country"json:"country"`
		City string 	`bson:"city"json:"city"`
	}
	fileInfo struct {
		jc.Collection	`bson:"-"json:"-"jc:"meta"`
		Kind string		`bson:"_id"`
		FileDate time.Time
		LastLine string
	}
	geoInfo struct {
		jc.Collection		`bson:"-"json:"-"jc:"geo_info"`
		Ip          string  `bson:"_id"json:"ip"`
		CountryCode string  `bson:"country_code"json:"country_code"`
		CountryName string  `bson:"country_name"json:"country_name"`
		RegionCode  string  `bson:"region_code"json:"region_code"`
		RegionName  string  `bson:"region_name"json:"region_name"`
		City        string  `bson:"city"json:"city"`
		ZipCode     string  `bson:"zip_code"json:"zip_code"`
		TimeZone    string  `bson:"time_zone"json:"time_zone"`
		Latitude    float32 `bson:"latitude"json:"latitude"`
		Longitude   float32 `bson:"longitude"json:"longitude"`
		MetroCode   int     `bson:"metro_code"json:"metro_code"`
	}
)

const (
	FULL_LINE = iota
	MONTH = iota
	DAY = iota
	TIME = iota
	HOSTNAME = iota
	PROCESS = iota
	PID = iota
	MSG = iota
)

const META_FILE_INFO = "file_info"

var (
	LOG_LINE *regexp.Regexp
	FAIL_MSG_INVALID_USER *regexp.Regexp
	FAIL_MSG_TOO_MANY_ATTEMPTS *regexp.Regexp
	FAIL_MSG_DISCONNECT *regexp.Regexp
)

func InitRegexp(){
	//                              month     day                time               hostname               process    pid   message
	LOG_LINE = regexp.MustCompile("^(\\w+)\\s+(\\d+)\\s+(\\d{2}:\\d{2}:\\d{2})\\s+([a-zA-z0-9\\-]+)\\s+(\\w+)\\[(\\d+)]:\\s(.*)$")

	//                                               msg_info                          ip_address
	FAIL_MSG_DISCONNECT = regexp.MustCompile("^Disconnected from (\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}).*")

	//                                                 msg_info     username                ip_address
	FAIL_MSG_INVALID_USER = regexp.MustCompile("^Invalid user (\\b.*\\b) from (\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}).*")

	//                                                                         msg_info                          username                  ip_address
	FAIL_MSG_TOO_MANY_ATTEMPTS = regexp.MustCompile("^error: maximum authentication attempts exceeded for (\\b\\S*\\b) from (\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}).*")
}

func logDate(logLine []string) (time.Time, error) {
	month := logLine[MONTH]
	day := logLine[DAY]
	time_ := logLine[TIME]
	return time.Parse(time.Stamp, fmt.Sprintf("%s %s %s", month, day, time_))
}

func isFileNew(firstLine []string) (bool, time.Time, error) {
	var err error
	var isNew bool
	var newTime time.Time

	// Get date stored in DB
	previousFile := fileInfo{}
	q, err := jc.NewQuery(&previousFile)
	if err != nil {
		return false, newTime, err
	}
	q.Filter(bson.M{"_id": META_FILE_INFO}).Execute(true)

	// Get date from current file line
	currentFileDate, err := logDate(firstLine)
	if err != nil {
		return false, newTime, err
	}

	// If DB query returned nothing
	if previousFile.FileDate.Equal(time.Time{}) {
		isNew = true
	} else {
		// Compare date from file with date from DB
		if !previousFile.FileDate.Equal(currentFileDate) {
			isNew = true
		}else {
			isNew = false
		}
	}
	if isNew {
		newTime = currentFileDate
	}
	return isNew, newTime, err
}

func ParseLogLine(line string) (match []string, err error) {
	captureGroups := LOG_LINE.FindAllStringSubmatch(line, -1)
	if len(captureGroups) == 0 {
		err = errors.New("line did not match expected pattern")
	}else {
		match = captureGroups[0]
	}
	return
}

func ProcessMsg(line string) (ip string, username string, err error) {
	var captureGroups [][]string

	captureGroups = FAIL_MSG_DISCONNECT.FindAllStringSubmatch(line, -1)
	if len(captureGroups) != 0 {
		fmt.Printf("Disconnect: %s\n", line)
		return  captureGroups[0][1], "", nil
	}

	captureGroups = FAIL_MSG_INVALID_USER.FindAllStringSubmatch(line, -1)
	if len(captureGroups) != 0 {
		fmt.Printf("Invalid User: %s\n", line)
		return captureGroups[0][2], captureGroups[0][1], nil
	}

	captureGroups = FAIL_MSG_TOO_MANY_ATTEMPTS.FindAllStringSubmatch(line, -1)

	if len(captureGroups) != 0 {
		fmt.Printf("Too many attempts: %s\n", line)
		return captureGroups[0][2], captureGroups[0][1], nil
	}

	err = errors.New("line did not match any pattern")
	return
}

func fetchGeoInfo(ip string) {
	info := geoInfo{}
	err := jc.NewDocument(&info)

	if err != nil {
		fmt.Println(err)
	}

	q, err := jc.NewQuery(&info)

	if err != nil {
		fmt.Println(err)
	}

	q.Filter(bson.M{"_id": ip}).Execute(true)

	if info.Ip != "" {
		fmt.Printf("Skipping already learned IP %s\n", ip)
		return
	}

	url := fmt.Sprintf("http://freegeoip.net/json/%s", ip)
	response, err := http.Get(url)

	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}
	rawBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}

	err = json.Unmarshal(rawBody, &info)

	if err != nil {
		fmt.Printf("Error: failed to Unmarshal json response. %s\n", err)
		return
	}
	info.Save(true)
	fmt.Printf("Geo info for %s: %s\n", ip, info)


}

func clearBacklog(filePath string) (err error) {
	var logFile *os.File
	var line []string
	var attempt authAttempt

	logFile, err = os.Open(filePath)
	if err != nil {
		return
	}
	defer logFile.Close()

	err = jc.NewDocument(&attempt)
	if err != nil {
		return
	}

	metaRecord := fileInfo{Kind: META_FILE_INFO}
	jc.NewDocument(&metaRecord)

	scanner := bufio.NewScanner(logFile)
	firstLine := true
	seeking := false
	lastRecordedLine := ""
	for scanner.Scan() {
		line, err = ParseLogLine(scanner.Text())
		if err != nil{
			continue
		}
		if firstLine {
			firstLine = false
			isNew, newDate, err := isFileNew(line)
			if err != nil {
				return err
			}
			if isNew {
				metaRecord.FileDate = newDate
				metaRecord.Save(true)
				seeking = false
			} else {
				q, err := jc.NewQuery(&metaRecord)
				if err != nil {
					return err
				}
				q.Filter(bson.M{"_id": META_FILE_INFO}).Execute(true)
				lastRecordedLine = metaRecord.LastLine
				seeking = true
			}
		}
		if seeking {
			if line[FULL_LINE] != lastRecordedLine {
				continue
			}else {
				fmt.Printf("Found match:\n%s\n%s\n", line[FULL_LINE], lastRecordedLine)
				seeking = false
				continue
			}
		}
		lastRecordedLine = line[FULL_LINE]
		ip, username, parseErr := ProcessMsg(line[MSG])
		if parseErr != nil {
			continue
		}
		attempt.NewImplicitID()
		attempt.Host = line[HOSTNAME]
		attempt.Date, _ = logDate(line)
		attempt.Ip = ip
		attempt.Username = username
		attempt.Save(true)
		go fetchGeoInfo(ip)

	}
	if lastRecordedLine != "" {
		metaRecord.LastLine = lastRecordedLine
		metaRecord.Save(true)
	}
	return nil
}


func WatchFile(filePath string) {
	err := clearBacklog(filePath)
	if err != nil {
		fmt.Println(err)
	}

	logWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		panic(err)
	}
	defer logWatcher.Close()

	err = logWatcher.Add(filePath)
	if err != nil {
		panic(err)
	}

	for {
		select {
		case event := <-logWatcher.Events:
			if event.Op == fsnotify.Write{
				clearBacklog(filePath)
			}
		case err := <-logWatcher.Errors:
			panic(err)
			break
		}
	}
}