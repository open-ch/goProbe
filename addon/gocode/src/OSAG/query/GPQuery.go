/////////////////////////////////////////////////////////////////////////////////
//
// GPQuery.go
//
// Query front end for goDB
//
// Written by Lennart Elsen
//        and Fabian  Kohn, July 2014
// Copyright (c) 2014 Open Systems AG, Switzerland
// All Rights Reserved.
//
/////////////////////////////////////////////////////////////////////////////////
/* This code has been developed by Open Systems AG
 *
 * goDB is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * goDB is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with goProbe; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/
package main

import (
    "bufio"
    "encoding/csv"
    "encoding/json"
    "flag"
    "fmt"
    "io/ioutil"
    "net"
    "os"
    "runtime"
    "sort"
    "strconv"
    "strings"
    "text/tabwriter"
    "time"
    //    "runtime/pprof"

    // database package for writing to and reading from the binary column store
    "OSAG/goDB"
)

const MAX_PRINTED_ENTRIES int = 1000
// Convert i to hexadecimal string
func itox(i uint, min int) string {

    // Assemble hexadecimal in reverse order.
    var b [32]byte
    bp := len(b)
    for ; i > 0 || min > 0; i /= 16 {
        bp--
        b[bp] = "0123456789abcdef"[byte(i%16)]
        min--
    }

    return string(b[bp:])
}

// Convert i to decimal string.
func itod(i uint) string {
    if i == 0 {
        return "0"
    }

    // Assemble decimal in reverse order.
    var b [32]byte
    bp := len(b)
    for ; i > 0; i /= 10 {
        bp--
        b[bp] = byte(i%10) + '0'
    }

    return string(b[bp:])
}

// parse macros file to find out about any external ips
func getExternalIPs() []string {
    var file *os.File
    var err error

    if file, err = os.Open("/etc/macros.conf"); err != nil {
        return []string{}
    }

    // scan file line by line
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        splits := strings.Split(scanner.Text(), "=")
        if splits[0] == "ip_LOCAL_EXT" {
            return strings.Split(splits[1], ",")
        }
    }

    return []string{}
}

// convert the ip byte arrays to string. The formatting logic for IPv6
// is directly copied over from the go IP package in order to save an
// additional import just for string operations
func rawIpToString(ip []byte) string {
    var (
        numZeros uint8 = 0
        iplen    int   = len(ip)
    )

    // count zeros in order to determine whether the address
    // is IPv4 or IPv6
    for i := 4; i < iplen; i++ {
        if (ip[i] & 0xFF) == 0x00 {
            numZeros++
        }
    }

    // construct ipv4 string
    if numZeros == 12 {
        return itod(uint(ip[0])) + "." +
            itod(uint(ip[1])) + "." +
            itod(uint(ip[2])) + "." +
            itod(uint(ip[3]))
    } else {
        /// START OF GOOGLE CODE SNIPPET ///
        p := ip

        // Find longest run of zeros.
        e0 := -1
        e1 := -1
        for i := 0; i < iplen; i += 2 {
            j := i
            for j < iplen && p[j] == 0 && p[j+1] == 0 {
                j += 2
            }
            if j > i && j-i > e1-e0 {
                e0 = i
                e1 = j
            }
        }

        // The symbol "::" MUST NOT be used to shorten just one 16 bit 0 field.
        if e1-e0 <= 2 {
            e0 = -1
            e1 = -1
        }

        // Print with possible :: in place of run of zeros
        var s string
        for i := 0; i < iplen; i += 2 {
            if i == e0 {
                s += "::"
                i = e1
                if i >= iplen {
                    break
                }
            } else if i > 0 {
                s += ":"
            }
            s += itox((uint(p[i])<<8)|uint(p[i+1]), 1)

        }
        return s
    }
}

// Helper routine to make numbers/bytes human readable
func humanize(val int, div int) string {
    count := 0
    var val_flt float64 = float64(val)

    units := map[int][]string{
        1024: []string{" B", "kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"},
        1000: []string{" ", "k", "M", "G", "T", "P", "E", "Z", "Y"},
    }

    for val > div {
        val /= div
        val_flt /= float64(div)
        count++
    }

    return fmt.Sprintf("%.2f %s", val_flt, units[div][count])
}

func IPStringToBytes(ip string) []byte {
    var is_ipv4 bool = strings.Contains(ip, ".")
    var cond_bytes []byte

    ipaddr := net.ParseIP(ip)
    for _, i := range ipaddr {
        cond_bytes = append(cond_bytes, byte(i))
    }

    // reorder the array if it is ipv4 and pad with  zeros
    if is_ipv4 {
        cond_bytes[0], cond_bytes[1], cond_bytes[2], cond_bytes[3] = ipaddr[12], ipaddr[13], ipaddr[14], ipaddr[15]

        for i := 4; i < 16; i++ {
            cond_bytes[i] = 0x00
        }
    }

    return cond_bytes
}

func AppendIfMissing(slice []string, s string) []string {
    for _, ele := range slice {
        if ele == s {
            return slice
        }
    }
    return append(slice, s)
}

// For the sorting we refer to closures to be able so sort by whatever value
// struct field we want
type Entry struct {
    k  goDB.Key
    v  goDB.Val
    nB uint64
    nP uint64
}

// By is the type of a "less" function that defines the ordering of its Planet arguments.
type By func(e1, e2 *Entry) bool

// Sort is a method on the function type, By, that sorts the argument slice according to the function
func (by By) Sort(entries []Entry) {
    es := &entrySorter{
        entries: entries,
        by:      by, // closure for sort order defintion
    }
    sort.Sort(es)
}

// planetSorter joins a By function and a slice of Planets to be sorted.
type entrySorter struct {
    entries []Entry
    by      func(e1, e2 *Entry) bool // closure for Less method
}

// Len is part of sort.Interface.
func (s *entrySorter) Len() int {
    return len(s.entries)
}

// Swap is part of sort.Interface.
func (s *entrySorter) Swap(i, j int) {
    s.entries[i], s.entries[j] = s.entries[j], s.entries[i]
}

// Less is part of sort.Interface. It is implemented by calling the "by" closure in the sorter.
func (s *entrySorter) Less(i, j int) bool {
    return s.by(&s.entries[i], &s.entries[j])
}

func ReadFlags(config *goDB.GeneralConf) {
    flag.StringVar(&config.Iface, "i", "", "Interface for which the query should be performed (e.g. eth0, t4_33760, ...)")
    flag.StringVar(&config.Conditions, "c", "", "Logical conditions for the query")
    flag.StringVar(&config.BaseDir, "d", "/usr/local/goProbe/data/db", "Path to database directory. By default, /usr/local/goProbe/data/db is used")
    flag.StringVar(&config.Format, "e", "txt", "Output format: {txt|json|csv}")
    flag.BoolVar(&config.Help, "h", false, "Prints the help page")
    flag.BoolVar(&config.HelpAdmin, "help-admin", false, "Prints the advanced help page")
    flag.BoolVar(&config.WipeAdmin, "wipe", false, "wipes the entire database")
    flag.Int64Var(&config.CleanAdmin, "clean", 0, "cleans all entries before indicated timestamp")
    flag.BoolVar(&config.External, "x", false, "Mode for external calls, e.g. from portal")
    flag.BoolVar(&config.Sort, "p", false, "Sort results by accumulated packets instead of bytes")
    flag.BoolVar(&config.SortAscending, "a", false, "Sort results in ascending order")
    flag.BoolVar(&config.Incoming, "in", false, "Take into account incoming data only (received packets/bytes)")
    flag.BoolVar(&config.Outgoing, "out", false, "Take into account outgoing data only (sent packets/bytes)")
    flag.IntVar(&config.NumResults, "n", 10000, "Maximum number of final entries to show. Defaults to 95% of the overall data volume / number of packets (depending on the '-p' parameter)")
    flag.Int64Var(&config.First, "f", 0, "Lower bound on flow timestamp")
    flag.Int64Var(&config.Last, "l", 9999999999999999, "Upper bound on flow timestamp")
    flag.Parse()

    config.QueryType = (flag.Arg(0))
}

func printHelpGenerator(external bool) func() {
    var helpString string
    if !external {
        helpString =
            `Usage:

                goquery -i <interface> [-hparvx] [-in|-out] [-n <max_n>] [-e txt|csv|json] [-d <db-path>]
                [-f <timestamp>] [-l <timestamp>] [-c <conditions>] [-s <column>] [-v verbosity] QUERY_TYPE

                Flow database query tool to extract flow statistics from the goDB database
                created by goProbe. By default, output is written to STDOUT, sorted by overall
                (incoming and outgoing) data volume in descending order.

                QUERY_TYPE
                Type of query to perform (top talkers or top applications):
                    talk_src        top talkers by source IP (default)
                    talk_dst        top talkers by destination IP
                    talk_conv       top talkers by IP pairs ("conversation")
                    apps_port       top applications by protocol:[port]
                    apps_dpi        top applications by deep packet inspection (L7)
                    agg_talk_port   aggregation of conversation and applications

                    -h
                        Display this help text.

                        -help-admin
                        Display advanced options for database maintenance.

                        -n
                        Maximum number of final entries to show. Defaults to 95% of the overall
                        data volume / number of packets (depending on the '-p' parameter)

                        -i
                        Interface for which the query should be performed (e.g. eth0, t4_33760, ...)

                        -in
                        Take into account incoming data only (received packets/bytes).

                        -out
                        Take into account outgoing data only (sent packets/bytes).

                        -e
                        Output format:
                        txt           Output in plain text format (default)
                        json          Output in JSON format
                        csv           Output in comma-separated table format

                        -d
                        Path to database directory <db-path>. By default,
                        /usr/local/goProbe/data/db is used.

                        -f
                        -l
                        Lower / upper bound on flow timestamp. Allowed formats are:
                        1357800683                             EPOCH

                        -c
                        Logical conditions for the query, e.g.
                        "dport=22 AND sip=192.168.0.1 AND proto=17"

                        Currently, only the "AND" and "=" operators are supported. 

                        -p
                        Sort results by accumulated packets instead of bytes.

                        -s
                        Sort results by given column name(s) (overrides -p option, if given).
                        -s time,sip,dport

                        -a
                        Sort results in ascending instead of descending order.

                        -x
                        Mode for external calls, e.g. from portal. Reduces verbosity of error
                        messages to customer friendly text and writes full error messages
                        to message log instead.

                        -t
                        Timeout for database query call (Default: 300s).
                        `
        return func() {
            fmt.Println(helpString)
        }
    } else {
        return func() {
            return
        }
    }

}

func printAdvancedHelpGenerator(external bool) func() {
    var advHelpString string
    if !external {
        advHelpString =
            `Advanced maintenance options (should not be used in interactive mode):

                    -wipe
                        Wipe all database entries from disk.
                        Handle with utmost care, all changes are permanent and cannot be undone!

                    -clean <timestamp>
                        Remove all database rows before given timestamp (retention time).
                        Handle with utmost care, all changes are permanent and cannot be undone!
                        Allowed formats are identical to -f/-l parameters.

                        `
        return func() {
            fmt.Println(advHelpString)
        }
    } else {
        return func() {
            return
        }
    }
}

var TimeFormats []string = []string{"1995:01:24T09:08:17.1823213",
    "1995-01-24T09:08:17.1823213",
    "Wed, 16 Jun 94 07:29:35 CST",
    "Thu, 13 Oct 94 10:13:13 -0700",
    "Wed, 9 Nov 1994 09:50:32 -0500 (EST)",
    "21 dec 17:05",
    "21-dec 17:05",
    "21/dec 17:05",
    "21/dec/93 17:05",
    "1999 10:02:18 GMT",
    "16 Nov 94 22:28:20 PST"}

func parseTimeArgument(timeString string) (int64, error) {
    var err error
    var t time.Time

    for _, tFormat := range TimeFormats {
        t, err = time.Parse(tFormat, timeString)
        if err == nil {
            return t.Unix(), err
        }
        fmt.Println(tFormat, t, err)
    }

    return int64(0), err
}

// completely removes all folders inside the base directory. Handle with care!
func wipeDB(dbPath string) error {
    // Get list of files in directory
    var dirList []os.FileInfo
    var err error

    if dirList, err = ioutil.ReadDir(dbPath); err != nil {
        return err
    }

    for _, file := range dirList {
        if file.IsDir() && (file.Name() != "./" || file.Name() != "../") {
            if rmerr := os.RemoveAll(dbPath + "/" + file.Name()); rmerr != nil {
                return rmerr
            }
        }
    }

    return err
}

// remove those directories whose timestamps are outside of the retention period
func cleanOldDBDirs(dbPath string, tOldest int64) error {
    // Get list of files in directory
    var (
        ifaceDirList []os.FileInfo
        dirList      []os.FileInfo
        err          error
        dir_name     string
        tfirst       int64
    )

    if ifaceDirList, err = ioutil.ReadDir(dbPath); err != nil {
        return err
    }

    // check all the interface directories for obsolete timestamps
    for _, iface := range ifaceDirList {
        if iface.IsDir() && (iface.Name() != "./" || iface.Name() != "../") {
            if dirList, err = ioutil.ReadDir(dbPath + "/" + iface.Name()); err != nil {
                return err
            }

            for _, file := range dirList {
                if file.IsDir() && (file.Name() != "./" || file.Name() != "../") {
                    dir_name = file.Name()
                    temp_dir_tstamp, _ := strconv.ParseInt(dir_name, 10, 64)

                    // check if the directory is within time frame of interest
                    if tfirst <= temp_dir_tstamp && temp_dir_tstamp < tOldest+goDB.DB_WRITE_INTERVAL {
                        // remove the directory
                        if rmerr := os.RemoveAll(dbPath + "/" + iface.Name() + "/" + dir_name); rmerr != nil {
                            return rmerr
                        }
                    }
                }
            }
        }
    }
    return err

}

// Message handling
func throwMsg(msg string, external bool, fmtSpec string) {
    customer_text := "An error occurred while retrieving the requested information"
    out_level := os.Stderr
    status := "error"

    if msg == "Query returned no results" {
        out_level = os.Stdout
        status = "ok"
    }

    // If called interactively, show full error message to user (otherwise show
    // customer friendly generic message)
    if !(msg != "Query returned no results" && external) {
        customer_text = msg
    }

    if fmtSpec == "json" {
        // If called non-interactively, write full error message to message log
        if external {
            if goDB.InitDBLog() != nil {
                return
            }
            goDB.SysLog.Err(msg)
        }
        message := map[string]string{
            "status":        status,
            "statusMessage": customer_text,
        }

        json_out, _ := json.Marshal(message)
        fmt.Fprintf(out_level, "%s", json_out)
    } else {
        fmt.Fprintf(out_level, "%s\n", customer_text)
    }
}

//--------------------------------------------------------------------------------
func main() {
    //--------------------------------------------------------------------------------

    // CPU Profiling Calls
    //runtime    runtime.SetBlockProfileRate(10000000) // PROFILING DEBUG
    //    f, proferr := os.Create("GPCore.prof")    // PROFILING DEBUG
    //    if proferr != nil {                       // PROFILING DEBUG
    //        fmt.Println("Profiling error: "+proferr.Error()) // PROFILING DEBUG
    //    } // PROFILING DEBUG
    //    pprof.StartCPUProfile(f)     // PROFILING DEBUG
    //    defer pprof.StopCPUProfile() // PROFILING DEBUG

    /// CPU & THREADING SETTINGS ///
    numCpu := runtime.NumCPU()
    runtime.GOMAXPROCS(numCpu)

    // Start timing
    tStart := time.Now()

    /// COMMAND LINE OPTIONS PARSING ///
    var queryConfig goDB.GeneralConf
    ReadFlags(&queryConfig)

    printHelp := printHelpGenerator(queryConfig.External)
    printAdvancedHelp := printAdvancedHelpGenerator(queryConfig.External)

    // check if only help needs to be printed
    if queryConfig.Help {
        printHelp()
        return
    }

    if queryConfig.HelpAdmin {
        printAdvancedHelp()
        return
    }

    // check if data needs to be cleaned or wiped
    if queryConfig.WipeAdmin {

        if wiperr := wipeDB(queryConfig.BaseDir); wiperr != nil {
            throwMsg("Failed to completely remove database: "+wiperr.Error(), queryConfig.External, queryConfig.Format)
            return
        }

        return
    }

    if queryConfig.CleanAdmin > 0 {
        // cleaning code
        if clerr := cleanOldDBDirs(queryConfig.BaseDir, queryConfig.CleanAdmin); clerr != nil {
            throwMsg("Database clean up failed: "+clerr.Error(), queryConfig.External, queryConfig.Format)
        }

        return
    }

    // Configuration sanity checks
    if queryConfig.Iface == "" {
        throwMsg("No interface specified", queryConfig.External, queryConfig.Format)
        printHelp()
        return
    }

    if (queryConfig.QueryType != "talk_conv" && queryConfig.QueryType != "talk_src" && queryConfig.QueryType != "talk_dst" && queryConfig.QueryType != "apps_port" && queryConfig.QueryType != "apps_dpi" && queryConfig.QueryType != "agg_talk_port") || (queryConfig.QueryType == "") {
        throwMsg("Invalid query type: "+queryConfig.QueryType, queryConfig.External, queryConfig.Format)
        printHelp()
        return
    }

    if (queryConfig.Last <= queryConfig.First) {
        throwMsg("Invalid time interval: the lower time bound cannot be greater than the upper time bound"+queryConfig.QueryType, queryConfig.External, queryConfig.Format)
        printHelp()
        return
    }

    /// QUERY PREPARATION ///
    // parse conditions
    var cond_attr string
    var cond_bytes []byte
    var err error

    var conditions []goDB.Condition

    if queryConfig.Conditions != "" {
        conditionStrings := strings.Split(queryConfig.Conditions, "AND")

        for _, cond := range conditionStrings {
            tmp_conds := strings.Split(strings.TrimSpace(cond), "=")

            if len(tmp_conds) == 1 {
                throwMsg("Missing argument to condition. Examples: \"l7proto=SSH\", \"dport=5353\"", queryConfig.External, queryConfig.Format)
                printHelp()
                return
            }

            cond_attr = tmp_conds[0]
            if tmp_conds[0] != "l7proto" && tmp_conds[0] != "dip" && tmp_conds[0] != "sip" && tmp_conds[0] != "proto" && tmp_conds[0] != "dport" {
                throwMsg("Unknown condition: "+queryConfig.Conditions, queryConfig.External, queryConfig.Format)
                printHelp()
                return
            }

            // translate the indicated value into bytes
            var num uint64
            var isIn bool

            switch cond_attr {
            case "l7proto":
                if num, err = strconv.ParseUint(tmp_conds[1], 10, 16); err != nil {
                    if num, isIn = goDB.GetDPIProtoID(tmp_conds[1]); isIn == false {
                        throwMsg("Could not parse condition value: "+err.Error(), queryConfig.External, queryConfig.Format)
                        return
                    }
                }

                cond_bytes = []byte{uint8(num >> 8), uint8(num & 0xff)}
            case "dip":
                cond_bytes = IPStringToBytes(tmp_conds[1])

                if cond_bytes == nil {
                    throwMsg("Could not parse IP address: "+tmp_conds[1], queryConfig.External, queryConfig.Format)
                    return
                }
            case "sip":
                cond_bytes = IPStringToBytes(tmp_conds[1])

                if cond_bytes == nil {
                    throwMsg("Could not parse IP address: "+tmp_conds[1], queryConfig.External, queryConfig.Format)
                    return
                }
            case "proto":
                if num, err = strconv.ParseUint(tmp_conds[1], 10, 16); err != nil {
                    if num, isIn = goDB.GetIPProtoID(tmp_conds[1]); isIn == false {
                        throwMsg("Could not parse condition value: "+err.Error(), queryConfig.External, queryConfig.Format)
                        return
                    }
                }

                cond_bytes = []byte{uint8(num & 0xff)}
            case "dport":
                if num, err = strconv.ParseUint(tmp_conds[1], 10, 16); err != nil {
                    throwMsg("Could not parse condition value: "+err.Error(), queryConfig.External, queryConfig.Format)
                    return
                }

                cond_bytes = []byte{uint8(num >> 8), uint8(num & 0xff)}
            }

            conditions = append(conditions, goDB.NewCondition(cond_attr, cond_bytes))
        }
    }

    /// DATA ACQUISITION AND PREPARATION ///
    // prepare the final map for
    FinalMap := make(map[goDB.Key]*goDB.Val)
    var SumBytesRcvd, SumBytesSent, SumPktsRcvd, SumPktsSent int

    // Channel for handling of returned maps
    mapChan := make(chan map[goDB.Key]*goDB.Val)
    quitChan := make(chan bool)

    // create workload
    var workload *goDB.GPWorkload
    var workErr  error
    if workload, workErr = goDB.NewGPWorkload(queryConfig.BaseDir + "/" + queryConfig.Iface); workErr != nil {
        throwMsg("Could not initialize query workload: "+err.Error(), queryConfig.External, queryConfig.Format)
        return
    }

    if err := workload.CreateWorkerJobs(queryConfig.First, queryConfig.Last); err != nil {
        throwMsg("Query returned no results", queryConfig.External, queryConfig.Format)
        return
    }

    // spawn reader workers and make them execute their tasks
    workload.ExecuteWorkerReadJobs(queryConfig.QueryType, conditions, mapChan, quitChan)

    // This is where the magic happens:
    // aggregate the maps created by the individual workers
    var num_finished int
    var num_workers int = workload.GetNumWorkers()

mapJoin:
    for {
        select {
        case item := <-mapChan:
            for k, v := range item {
                SumBytesRcvd += int(v.NBytesRcvd)
                SumBytesSent += int(v.NBytesSent)
                SumPktsRcvd += int(v.NPktsRcvd)
                SumPktsSent += int(v.NPktsSent)

                if toUpdate, exists := FinalMap[k]; exists {
                    toUpdate.NBytesRcvd += v.NBytesRcvd
                    toUpdate.NBytesSent += v.NBytesSent
                    toUpdate.NPktsRcvd += v.NPktsRcvd
                    toUpdate.NPktsSent += v.NPktsSent
                } else {
                    FinalMap[k] = &goDB.Val{v.NBytesRcvd, v.NBytesSent, v.NPktsRcvd, v.NPktsSent}
                }
            }
        case quit := <-quitChan:
            if quit {
                num_finished++
            }
            if num_finished == num_workers {
                break mapJoin
            }
        }
    }

    if len(FinalMap) == 0 {
        throwMsg("Query returned no results", queryConfig.External, queryConfig.Format)
        return
    }

    tStop := time.Now()

    /// DATA PRESENATION ///
    // prepare header
    var header []string
    var sorting string = "accumulated "

    if queryConfig.Sort {
        sorting += "packets "
    } else {
        sorting += "data volume "
    }

    if queryConfig.Incoming && !queryConfig.Outgoing {
        sorting += "(received only)"
    } else if !queryConfig.Incoming && queryConfig.Outgoing {
        sorting += "(sent only)"
    } else {
        sorting += "(sent and received)"
    }

    switch queryConfig.QueryType {
    case "talk_conv":
        header = append(header, "sip", "dip")
    case "talk_src":
        header = append(header, "sip")
    case "talk_dst":
        header = append(header, "dip")
    case "apps_port":
        header = append(header, "dport", "proto")
    case "apps_dpi":
        header = append(header, "l7proto", "category")
    case "agg_talk_port":
        header = append(header, "sip", "dip", "dport", "proto")
    }

    header = append(header, "packets", "%", "data vol.", "%")

    wtxt := tabwriter.NewWriter(os.Stdout, 0, 1, 3, ' ', tabwriter.AlignRight)
    wcsv := csv.NewWriter(os.Stdout)
    var wjson map[string]interface{}
    var json_row_data []map[string]interface{}

    switch queryConfig.Format {
    case "txt":
        fmt.Println("Your query:", queryConfig.QueryType)
        fmt.Println("Conditions:", queryConfig.Conditions)
        fmt.Println("Sort by:   ", sorting)
        fmt.Println("Interface: ", queryConfig.Iface)
        fmt.Println("Query produced", len(FinalMap), "hits and took", tStop.Sub(tStart).String(), "\n")
        fmt.Fprintln(wtxt, strings.Join(header, "\t")+"\t")
    case "csv":
        wcsv.Write(header)
    case "json":
        header[len(header)-1] = "bytes_percent"
        header[len(header)-2] = "bytes"
        header[len(header)-3] = "packets_percent"
        header[len(header)-4] = "packets"
    }

    var num_printed int
    var sum_packets, sum_bytes int

    // The actual sorting functions
    var Bytes, Packets func(e1, e2 *Entry) bool

    if queryConfig.SortAscending {
        Bytes = func(e1, e2 *Entry) bool {
            return e1.nB < e2.nB
        }
        Packets = func(e1, e2 *Entry) bool {
            return e1.nP < e2.nP
        }
    } else {
        Bytes = func(e1, e2 *Entry) bool {
            return e1.nB > e2.nB
        }
        Packets = func(e1, e2 *Entry) bool {
            return e1.nP > e2.nP
        }
    }

    var mapEntries []Entry = make([]Entry, len(FinalMap))
    count := 0
    for key, val := range FinalMap {
        mapEntries[count].k = key
        mapEntries[count].v = *val
        if queryConfig.Incoming && !queryConfig.Outgoing {
            mapEntries[count].nB = val.NBytesRcvd
            mapEntries[count].nP = val.NPktsRcvd
        } else if !queryConfig.Incoming && queryConfig.Outgoing {
            mapEntries[count].nB = val.NBytesSent
            mapEntries[count].nP = val.NPktsSent
        } else {
            mapEntries[count].nB = val.NBytesRcvd + val.NBytesSent
            mapEntries[count].nP = val.NPktsRcvd + val.NPktsSent
        }
        count++
    }

    if queryConfig.Sort {
        By(Packets).Sort(mapEntries)
    } else {
        By(Bytes).Sort(mapEntries)
    }

    for _, map_entry := range mapEntries {
        if num_printed < queryConfig.NumResults && num_printed < MAX_PRINTED_ENTRIES {
            var elements []interface{}
            switch queryConfig.QueryType {
            case "talk_conv":
                elements = append(elements, rawIpToString(map_entry.k.Sip[:]), rawIpToString(map_entry.k.Dip[:]))
            case "talk_src":
                elements = append(elements, rawIpToString(map_entry.k.Sip[:]))
            case "talk_dst":
                elements = append(elements, rawIpToString(map_entry.k.Dip[:]))
            case "apps_port":
                if queryConfig.Format != "json" {
                    elements = append(elements, strconv.Itoa(int(uint16(map_entry.k.Dport[0])<<8|uint16(map_entry.k.Dport[1]))), goDB.GetIPProto(int(map_entry.k.Protocol)))
                } else {
                    elements = append(elements, int(uint16(map_entry.k.Dport[0])<<8|uint16(map_entry.k.Dport[1])), goDB.GetIPProto(int(map_entry.k.Protocol)))
                }
            case "apps_dpi":
                l7proto, category := goDB.GetDPIProtoCat(int(uint16(map_entry.k.L7proto[0])<<8 | uint16(map_entry.k.L7proto[1])))
                if l7proto=="" {
                    l7proto = "Unknown"
                }
                if category=="" {
                    category = "Uncategorised"
                }

                elements = append(elements, l7proto, category)
            case "agg_talk_port":
                if queryConfig.Format != "json" {
                elements = append(elements,
                    rawIpToString(map_entry.k.Sip[:]), rawIpToString(map_entry.k.Dip[:]),
                    strconv.Itoa(int(uint16(map_entry.k.Dport[0])<<8|uint16(map_entry.k.Dport[1]))), goDB.GetIPProto(int(map_entry.k.Protocol)))
                } else {
                elements = append(elements,
                    rawIpToString(map_entry.k.Sip[:]), rawIpToString(map_entry.k.Dip[:]),
                    strconv.Itoa(int(uint16(map_entry.k.Dport[0])<<8|uint16(map_entry.k.Dport[1]))), goDB.GetIPProto(int(map_entry.k.Protocol)))
                }
            }

            if queryConfig.Incoming && !queryConfig.Outgoing {
                sum_packets = int(SumPktsRcvd)
                sum_bytes = int(SumBytesRcvd)

                // catch division by zero
                if sum_packets == 0 {
                    sum_packets = 1
                }
                if sum_bytes == 0 {
                    sum_bytes = 1
                }

                if queryConfig.Format == "txt" {
                    elements = append(elements, humanize(int(map_entry.v.NPktsRcvd), 1000), strconv.FormatFloat(100.*float64(map_entry.v.NPktsRcvd)/float64(sum_packets), 'f', 2, 64))
                    elements = append(elements, humanize(int(map_entry.v.NBytesRcvd), 1024), strconv.FormatFloat(100.*float64(map_entry.v.NBytesRcvd)/float64(sum_bytes), 'f', 2, 64))
                } else if queryConfig.Format == "json" {
                    elements = append(elements, uint64(map_entry.v.NPktsRcvd), 100.*float64(map_entry.v.NPktsRcvd)/float64(sum_packets))
                    elements = append(elements, uint64(map_entry.v.NBytesRcvd), 100.*float64(map_entry.v.NBytesRcvd)/float64(sum_bytes))
                } else {
                    elements = append(elements, strconv.FormatUint(uint64(map_entry.v.NPktsRcvd), 10), strconv.FormatFloat(100.*float64(map_entry.v.NPktsRcvd)/float64(sum_packets), 'f', 2, 64))
                    elements = append(elements, strconv.FormatUint(uint64(map_entry.v.NBytesRcvd), 10), strconv.FormatFloat(100.*float64(map_entry.v.NBytesRcvd)/float64(sum_bytes), 'f', 2, 64))
                }
            } else if !queryConfig.Incoming && queryConfig.Outgoing {
                sum_packets = int(SumPktsSent)
                sum_bytes = int(SumBytesSent)

                // catch division by zero
                if sum_packets == 0 {
                    sum_packets = 1
                }
                if sum_bytes == 0 {
                    sum_bytes = 1
                }

                if queryConfig.Format == "txt" {
                    elements = append(elements, humanize(int(map_entry.v.NPktsSent), 1000), strconv.FormatFloat(100.*float64(map_entry.v.NPktsSent)/float64(sum_packets), 'f', 2, 64))
                    elements = append(elements, humanize(int(map_entry.v.NBytesSent), 1024), strconv.FormatFloat(100.*float64(map_entry.v.NBytesSent)/float64(sum_bytes), 'f', 2, 64))
                } else if queryConfig.Format == "json" {
                    elements = append(elements, uint64(map_entry.v.NPktsSent), 100.*float64(map_entry.v.NPktsSent)/float64(sum_packets))
                    elements = append(elements, uint64(map_entry.v.NBytesSent), 100.*float64(map_entry.v.NBytesSent)/float64(sum_bytes))
                } else {
                    elements = append(elements, strconv.FormatUint(uint64(map_entry.v.NPktsSent), 10), strconv.FormatFloat(100.*float64(map_entry.v.NPktsSent)/float64(sum_packets), 'f', 2, 64))
                    elements = append(elements, strconv.FormatUint(uint64(map_entry.v.NBytesSent), 10), strconv.FormatFloat(100.*float64(map_entry.v.NBytesSent)/float64(sum_bytes), 'f', 2, 64))
                }
            } else {
                sum_packets = int(SumPktsRcvd + SumPktsSent)
                sum_bytes = int(SumBytesRcvd + SumBytesSent)

                // catch division by zero
                if sum_packets == 0 {
                    sum_packets = 1
                }
                if sum_bytes == 0 {
                    sum_bytes = 1
                }

                if queryConfig.Format == "txt" {
                    elements = append(elements, humanize(int(map_entry.v.NPktsRcvd+map_entry.v.NPktsSent), 1000), strconv.FormatFloat(100.*float64(map_entry.v.NPktsRcvd+map_entry.v.NPktsSent)/float64(sum_packets), 'f', 2, 64))
                    elements = append(elements, humanize(int(map_entry.v.NBytesRcvd+map_entry.v.NBytesSent), 1024), strconv.FormatFloat(100.*float64(map_entry.v.NBytesRcvd+map_entry.v.NBytesSent)/float64(sum_bytes), 'f', 2, 64))
                } else if queryConfig.Format == "json" {
                    elements = append(elements, int(map_entry.v.NPktsRcvd+map_entry.v.NPktsSent), 100.*float64(map_entry.v.NPktsRcvd+map_entry.v.NPktsSent)/float64(sum_packets))
                    elements = append(elements, int(map_entry.v.NBytesRcvd+map_entry.v.NBytesSent), 100.*float64(map_entry.v.NBytesRcvd+map_entry.v.NBytesSent)/float64(sum_bytes))
                } else {
                    elements = append(elements, strconv.FormatUint(uint64(map_entry.v.NPktsRcvd+map_entry.v.NPktsSent), 10), strconv.FormatFloat(100.*float64(map_entry.v.NPktsRcvd+map_entry.v.NPktsSent)/float64(sum_packets), 'f', 2, 64))
                    elements = append(elements, strconv.FormatUint(uint64(map_entry.v.NBytesRcvd+map_entry.v.NBytesSent), 10), strconv.FormatFloat(100.*float64(map_entry.v.NBytesRcvd+map_entry.v.NBytesSent)/float64(sum_bytes), 'f', 2, 64))
                }
            }

            switch queryConfig.Format {
            case "txt":
                strele := make([]string, len(elements))
                for i, v := range elements {
                    strele[i] = v.(string)
                }
                fmt.Fprintln(wtxt, strings.Join(strele, "\t")+"\t")
            case "csv":
                strele := make([]string, len(elements))
                for i, v := range elements {
                    strele[i] = v.(string)
                }
                wcsv.Write(strele)
            case "json":
                json_row := make(map[string]interface{})

                for i, title := range header {
                    json_row[title] = elements[i]
                }

                json_row_data = append(json_row_data, json_row)
            }
        }

        num_printed++
    }

    switch queryConfig.Format {
    case "txt":
        wtxt.Flush()
        fmt.Println("\nOverall packets:", humanize(sum_packets, 1000), ", Overall data volume:", humanize(sum_bytes, 1024))
    case "csv":
        wcsv.Write([]string{"Overall packets", strconv.Itoa(sum_packets)})
        wcsv.Write([]string{"Overall data volume (bytes)", strconv.Itoa(sum_bytes)})
        wcsv.Write([]string{"Sorting and flow direction", sorting})
        wcsv.Write([]string{"Interface", queryConfig.Iface})
        wcsv.Flush()
    case "json":
        wjson = make(map[string]interface{})

        wjson["status"] = "ok"
        wjson[queryConfig.QueryType] = json_row_data
        wjson["summary"] = map[string]interface{}{
            "interface":     queryConfig.Iface,
            "total_packets": sum_packets,
            "total_bytes":   sum_bytes,
        }
        wjson["ext_ips"] = getExternalIPs()

        // encode the json data
        var json_bytes []byte
        var err error

        if json_bytes, err = json.Marshal(wjson); err != nil {
            throwMsg("Failed to create json data: "+err.Error(), queryConfig.External, queryConfig.Format)
            return
        }

        if queryConfig.External {
            fmt.Printf(string(json_bytes))
        } else {
            fmt.Println(string(json_bytes))
        }
    }

    return
}
