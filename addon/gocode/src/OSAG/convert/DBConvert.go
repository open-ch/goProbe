///////////////////////////////////////////////////////////////////////////////// 
// 
// DBConvert.go 
// 
// Binary to read in database data from csv files and push it to the goDB writer
// which creates a .gpf columnar database from the data at a specified location.
// 
// Written by Lennart Elsen, July 2014
//        and Fabian  Kohn
// Copyright (c) 2014 Open Systems AG, Switzerland 
// All Rights Reserved.
//
/////////////////////////////////////////////////////////////////////////////////
/* This code has been developed by Open Systems AG
 *
 * goProbe is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * goProbe is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with goProbe; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/
package main

import(
    // OSAG DB packages
    "OSAG/goDB"

    "os"
    "os/exec"
    "bufio"
    "strings"
    "strconv"
    "runtime"
    "runtime/debug"

    "fmt"
    "flag"
)

type Config struct {
    Iface    string
    FilePath string
    SavePath string
    NumLines int
}

// parameter governing the number of seconds that are covered by a block
const DB_WRITE_INTERVAL int64 = 300

func parseCommandLineArgs(cfg *Config){
    flag.StringVar(&cfg.Iface, "i", "", "Interface from which the data originated")
    flag.StringVar(&cfg.FilePath, "f", "", "CSV file from which the data should be read")
    flag.StringVar(&cfg.SavePath, "s", "", "Folder to which the .gpf files should be written")
    flag.IntVar(&cfg.NumLines, "n", 111222333444, "Number of rows to read from the CSV file")
    flag.Parse()
}

func main(){

    // specify number of threads that can be used
    numCpu := runtime.NumCPU()
    runtime.GOMAXPROCS(numCpu)

    // parse command line arguments
    var config Config
    parseCommandLineArgs(&config)

    // sanity check the input
    if config.FilePath == "" || config.SavePath == "" {
        fmt.Println("Empty path specified. Usage: ./goConvert -i <interface> -f <file path> -s <save path>")
        return
    }

    if config.Iface == "" {
        fmt.Println("No interface specified. Usage: ./goConvert -i <interface> -f <file path> -s <save path>")
        return
    }

    // get number of lines to read in the specified file
    cmd         := exec.Command("wc", "-l", config.FilePath)
    out, cmderr := cmd.Output()
    if cmderr != nil {
        fmt.Println("Could not execute line count on file", config.FilePath)
        return
    }

    nlString      := strings.Split(string(out), " ")
    nl_in_file, _ := strconv.ParseInt(nlString[0], 10, 32)
    if int(nl_in_file) < config.NumLines && nl_in_file > 0 {
        config.NumLines = int(nl_in_file)
    }

    fmt.Printf("Converting %d rows in file %s\n", config.NumLines, config.FilePath)

    // create channel to pass to the storage writer
    dataChan := make(chan goDB.DBData)
    doneChan := make(chan bool)

    // init goprobe log
    goDB.InitDBLog()

    // open file
    var(
        file *os.File
        err  error
        br, bs, pr, ps []byte
        dip, sip []byte
        dport, l7proto, proto []byte
    )

    if file, err = os.Open(config.FilePath); err != nil {
        fmt.Println("File open error: "+err.Error())
    }

    // spawn database writer
    writer := goDB.NewDBStorageWrite(config.SavePath)
    writer.WriteFlowsToDatabase(int64(0), dataChan, doneChan)

    fmt.Print("Progress:   0% |")

go func(){
    // scan file line by line
    scanner := bufio.NewScanner(file)
    var lines_read int
    var active_block_stamp int64
    var perc_done, prev_perc int

    var prev_block_stamp int64

    for scanner.Scan() {
        if lines_read == config.NumLines {
            break
        }

        perc_done = int(float64(lines_read)/float64(config.NumLines)*100)
        if perc_done != prev_perc {
            if perc_done % 50 == 0 {
                fmt.Print(" 50% ")
                runtime.GC()
                debug.FreeOSMemory()
            } else if perc_done % 10 == 0 {
                fmt.Printf("|")
                runtime.GC()
                debug.FreeOSMemory()
            } else if perc_done % 2 == 0 {
                fmt.Printf("-")
                runtime.GC()
                debug.FreeOSMemory()
            }
        }
        prev_perc = perc_done

        fields := strings.Split(scanner.Text(), ",")

        // handle timestamp to find out when to ship the DBData to the channel
        time, _ := strconv.ParseInt(fields[9], 10, 64)

        // ignore all those lines which do not abide by the temporal ordering
        if time < prev_block_stamp {
            prev_block_stamp = time
            continue
        }

        cur_block_stamp := time - (time % DB_WRITE_INTERVAL)

        // if the timestamp is in another interval, create a new DBData block
        if cur_block_stamp != active_block_stamp {
            if active_block_stamp != 0 {

                var tstampArr = []byte{uint8(active_block_stamp>>56),
                    uint8(active_block_stamp>>48),
                    uint8(active_block_stamp>>40),
                    uint8(active_block_stamp>>32),
                    uint8(active_block_stamp>>24),
                    uint8(active_block_stamp>>16),
                    uint8(active_block_stamp>>8),
                    uint8(active_block_stamp&0xff)}

                // place the timestamp at the end of the arrays
                br      = append(br, tstampArr...)
                bs      = append(bs, tstampArr...)
                pr      = append(pr, tstampArr...)
                ps      = append(ps, tstampArr...)

                dip     = append(dip,     tstampArr...)
                sip     = append(sip,     tstampArr...)
                dport   = append(dport,   tstampArr...)
                l7proto = append(l7proto, tstampArr...)
                proto   = append(proto,   tstampArr...)

                // if the block was switched write out the current arrays
                dataChan <- goDB.NewDBData(br, bs, pr, ps, dip, sip, dport, l7proto, proto, active_block_stamp, config.Iface)

                // reset the arrays
                br, bs, pr, ps        = []byte{}, []byte{}, []byte{}, []byte{}
                dip, sip              = []byte{}, []byte{}
                dport, l7proto, proto = []byte{}, []byte{}, []byte{}

                // the new timestamp becomes the active timestamp
                active_block_stamp = cur_block_stamp

                var tstampArrNew = []byte{uint8(active_block_stamp>>56),
                    uint8(active_block_stamp>>48),
                    uint8(active_block_stamp>>40),
                    uint8(active_block_stamp>>32),
                    uint8(active_block_stamp>>24),
                    uint8(active_block_stamp>>16),
                    uint8(active_block_stamp>>8),
                    uint8(active_block_stamp&0xff)}

                // place the new timestamp at the beginning of the arrays
                br      = append(br, tstampArrNew...)
                bs      = append(bs, tstampArrNew...)
                pr      = append(pr, tstampArrNew...)
                ps      = append(ps, tstampArrNew...)

                dip     = append(dip,     tstampArrNew...)
                sip     = append(sip,     tstampArrNew...)
                dport   = append(dport,   tstampArrNew...)
                l7proto = append(l7proto, tstampArrNew...)
                proto   = append(proto,   tstampArrNew...)
            } else {
                active_block_stamp = cur_block_stamp

                var tstampArr = []byte{uint8(active_block_stamp>>56),
                    uint8(active_block_stamp>>48),
                    uint8(active_block_stamp>>40),
                    uint8(active_block_stamp>>32),
                    uint8(active_block_stamp>>24),
                    uint8(active_block_stamp>>16),
                    uint8(active_block_stamp>>8),
                    uint8(active_block_stamp&0xff)}

                // place the timestamp at the beginning of the arrays
                br      = append(br, tstampArr...)
                bs      = append(bs, tstampArr...)
                pr      = append(pr, tstampArr...)
                ps      = append(ps, tstampArr...)

                dip     = append(dip,     tstampArr...)
                sip     = append(sip,     tstampArr...)
                dport   = append(dport,   tstampArr...)
                l7proto = append(l7proto, tstampArr...)
                proto   = append(proto,   tstampArr...)
            }
        }

        // handle counters
        br_int, _ := strconv.ParseUint(fields[0], 10, 64)
        br = append(br,
            uint8(br_int>>56), uint8(br_int>>48),
            uint8(br_int>>40), uint8(br_int>>32),
            uint8(br_int>>24), uint8(br_int>>16),
            uint8(br_int>>8), uint8(br_int&0xff))
        bs_int, _ := strconv.ParseUint(fields[1], 10, 64)
        bs = append(bs,
            uint8(bs_int>>56), uint8(bs_int>>48),
            uint8(bs_int>>40), uint8(bs_int>>32),
            uint8(bs_int>>24), uint8(bs_int>>16),
            uint8(bs_int>>8), uint8(bs_int&0xff))
        pr_int, _ := strconv.ParseUint(fields[5], 10, 64)
        pr = append(pr,
            uint8(pr_int>>56), uint8(pr_int>>48),
            uint8(pr_int>>40), uint8(pr_int>>32),
            uint8(pr_int>>24), uint8(pr_int>>16),
            uint8(pr_int>>8), uint8(pr_int&0xff))
        ps_int, _ := strconv.ParseUint(fields[6], 10, 64)
        ps = append(ps,
            uint8(ps_int>>56), uint8(ps_int>>48),
            uint8(ps_int>>40), uint8(ps_int>>32),
            uint8(ps_int>>24), uint8(ps_int>>16),
            uint8(ps_int>>8), uint8(ps_int&0xff))

        // handle ips
        dip_str := strings.Split(fields[2],".")
        for i:=0; i<16; i++{
            if i<4 {
                octet, _ := strconv.Atoi(dip_str[i])
                dip = append(dip, uint8(octet))
            } else {
                dip = append(dip, 0x00)
            }
        }
        sip_str := strings.Split(fields[8],".")
        for i:=0; i<16; i++{
            if i<4 {
                octet, _ := strconv.Atoi(sip_str[i])
                sip = append(sip, uint8(octet))
            } else {
                sip = append(sip, 0x00)
            }
        }

        // handle port and protos
        prot_num, _ := strconv.Atoi(fields[7])
        proto = append(proto, uint8(prot_num))

        dport_num, _ := strconv.Atoi(fields[3])
        dport = append(dport, uint8(dport_num>>8), uint8(dport_num&0xff))

        l7p_num, _ := strconv.Atoi(fields[4])
        l7proto = append(l7proto, uint8(l7p_num>>8), uint8(l7p_num&0xff))

        lines_read++

        prev_block_stamp = cur_block_stamp
    }

    // push empty DBData onto channel to signal that we are done
    dataChan <- goDB.DBData{}

    fmt.Print("| 100%")
}()
    // return if the data write failed or exited
    if <- doneChan {
        fmt.Println("\nExiting")
        return
    }

    return
}
