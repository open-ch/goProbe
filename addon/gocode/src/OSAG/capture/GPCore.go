/////////////////////////////////////////////////////////////////////////////////
//
// GPCore.go
//
// Core process that interacts with all interfaces which are captured. Responsible 
// for timing database write outs and logging information. The Main function is
// located here.
//
// Written by Lennart Elsen
//        and Fabian  Kohn, May 2014
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

import (
    "syscall"
    "time"
    "sync"

    // for error messages not passed through syslog
    "fmt"

    // profiling & system tools
    "os"
    "os/signal"
    "runtime"
    "runtime/debug"

    // own packages
    "OSAG/goProbe"
    "OSAG/goDB"
)

// Fixed config parameters
const DB_WRITE_INTERVAL        = 300
const SnapLen           int32  = 90
const PromiscMode       bool   = true
const BpfFilterString   string = "not arp and not icmp and not icmp6 and not dst port 5551"
const DBPath            string = "/usr/local/goProbe/data/db"
const PcapStatsFilename string = "pcap_stats.csv"

func writeToStatsFile(data string, pathToFile string) {
    // open stats file for writing and write column descriptions in there
    var (
        err             error
        statsFileHandle *os.File
    )

    if statsFileHandle, err = os.OpenFile(pathToFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644); err != nil {
        goProbe.SysLog.Err("Opening file " + pathToFile + " failed: " + err.Error())
    }

    // header of csv file: "pkts_rcvd,iface,pkts_dropped,pkts_if_dropped"
    if _, wrerr := statsFileHandle.WriteString(data); wrerr != nil {
        goProbe.SysLog.Err("Writing data to " + pathToFile + " failed: " + err.Error())
    }

    // close the file
    statsFileHandle.Close()
}

//--------------------------------------------------------------------------------
func main() {
//--------------------------------------------------------------------------------

    /// LOGGING SETUP ///
    // initialize logger
    if err := goProbe.InitGPLog(); err != nil {
        fmt.Fprintf(os.Stderr, "Failed to initialize Logger. Exiting!\n")
        return
    }
    goProbe.SysLog.Info("Started goProbe")

    // Get command line arguments (all interface names)
    var IfaceNames []string = os.Args[1:]

    // exit program if the interfaces have not been correctly passed
    // by the configuration file. In this case, it does not make any
    // sense to keep running the probe
    if len(IfaceNames) == 0 {
        goProbe.SysLog.Crit("No interfaces have been specified in the configuration file (mandatory). Exiting.")
        return
    }

    /// CHANNEL VARIABLE SETUP ///
    // channel for handling writes to the flow map and the database
    gpcThreadIsDoneWritingChan := make(chan bool, 1)
    isDoneWritingToDBChan := make(chan bool, 1)

    // base channel which will be filled with row data from the GPMatrix
    DBDataChan := make(chan goDB.DBData, 1024)

    // channel for handling SIGTERM, SIGINT from the OS
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGUSR1, os.Interrupt)

    /// DB WRITER SETUP///
    toStorageWriter := goDB.NewDBStorageWrite(DBPath)

    /// CAPTURE INTERFACE SETUP ///
    // channel for handling termination signals from the individual
    // interfaces
    gpcThreadTerminatedChan := make(chan string, len(IfaceNames))

    // map of all interfaces that should be captured
    var gpcCaptureThreads map[string]*goProbe.GPCapture = make(map[string]*goProbe.GPCapture)

    for i := 0; i < len(IfaceNames); i++ {
        // assign new capture interface
        gpcCaptureThreads[IfaceNames[i]] = goProbe.NewGPCapture(IfaceNames[i],
            DBDataChan,
            gpcThreadIsDoneWritingChan)
    }

    // initialize dpi library
    if dpierr := goProbe.InitDPI(); dpierr != nil {
        goProbe.SysLog.Crit("DPI: " + dpierr.Error())
        return
    }

    /// CAPTURING THREADS ///

    // create wait group which is used to block the signal handler until
    // all capture threads have at least tried to start up
    var ctWG, ifaceWG sync.WaitGroup
    ctWG.Add(len(IfaceNames))

    // call the capture functions for each interface
    for _, gpcThread := range gpcCaptureThreads {
        ifaceWG.Add(1)

        // spawn the capturing thread
        gpcThread.CaptureInterface(SnapLen,
            PromiscMode,
            BpfFilterString,
            gpcThreadTerminatedChan, &ifaceWG)

        ifaceWG.Wait()
        ctWG.Done()

        // wait some time to allow the previous capturing thread to fire up
        time.Sleep(100 * time.Millisecond)
    }

    /// TICKER THAT INITIATES DB WRITING/GPC THREAD TERMINATION HANDLER ///
    // timer routine that initiates the write out to the database
    ticker := time.NewTicker(time.Second * time.Duration(DB_WRITE_INTERVAL))
    go func() {
        for {
            select {
            case t := <-ticker.C:
                goProbe.SysLog.Debug("Initiating flow data flush")

                // take the current timestamp and provide it to each capture thread in order
                // to prepare data
                timestamp := t.Unix()

                // wait for data and write it out when received
                toStorageWriter.WriteFlowsToDatabase(timestamp, DBDataChan, isDoneWritingToDBChan)

                // get the data from the individual maps
                statsString := ""
                for _, gpcThread := range gpcCaptureThreads {
                    gpcThread.SendWriteDBString(timestamp)
                    <-gpcThreadIsDoneWritingChan // wait for completion of data creation before continuing
                    statsString += gpcThread.GetPcapHandleStats(timestamp)
                }

                // signal that there will be no more data following on the channel
                DBDataChan <- goDB.DBData{}

                // block until the storage writer is done
                <-isDoneWritingToDBChan

                // write pcap handle stats to file
                writeToStatsFile(statsString, DBPath+"/"+PcapStatsFilename)

                // recover unavailable interfaces
                for i := 0; i < len(IfaceNames); i++ {
                    if _, ok := gpcCaptureThreads[IfaceNames[i]]; !ok {
                        goProbe.SysLog.Warning("Interface " + IfaceNames[i] + " not up, trying to restart...")

                        // (re-)assign new capture interface
                        gpcCaptureThreads[IfaceNames[i]] = goProbe.NewGPCapture(IfaceNames[i],
                            DBDataChan,
                            gpcThreadIsDoneWritingChan)

                        ifaceWG.Add(1)
                        // start capturing on it
                        gpcCaptureThreads[IfaceNames[i]].CaptureInterface(SnapLen,
                            PromiscMode,
                            BpfFilterString,
                            gpcThreadTerminatedChan, &ifaceWG)

                        ifaceWG.Wait()
                        // wait some time to allow the previous capturing thread to fire up
                        time.Sleep(100 * time.Millisecond)
                    }
                }

                // call the garbage collectors
                runtime.GC()
                debug.FreeOSMemory()

            case interfaceToKill := <-gpcThreadTerminatedChan:
                goProbe.SysLog.Warning("Capture on interface " + interfaceToKill + " terminated. Deleting it from map")

                // if something was received on the termination channel, delete the respective
                // interface from the map of active interfaces
                delete(gpcCaptureThreads, interfaceToKill)
            }
        }
    }()

    /// SIGNAL HANDLING ///

    // wait for all capture threads to start
    ctWG.Wait()
    goProbe.SysLog.Debug("interface capture routines initiated. Accepting signals...")

    for {
        // read signal from signal channel
        s := <-sigChan

        // take the current timestamp and provide it to each capture thread in order
        // to prepare data
        timestamp := time.Now().Unix()

        // if SIGUSER (10) is received, the program should write out a pcap stats report
        // to the stats file, which can be handled by the goprobe.init script
        if s == syscall.SIGUSR1 {

            goProbe.SysLog.Info("Received SIGUSR1 signal: writing out pcap handle stats")

            // get the stats data from the individual maps
            statsString := ""
            for _, gpcThread := range gpcCaptureThreads {
                statsString += gpcThread.GetPcapHandleStats(timestamp)
            }

            // write pcap handle stats to file
            writeToStatsFile(statsString, DBPath+"/"+PcapStatsFilename)

            // wait for a termination signal. If it is received, initiate a database flush
            // and terminate the program
        } else if s == syscall.SIGTERM || s == os.Interrupt {
            goProbe.SysLog.Info("Received SIGTERM/SIGINT signal: flushing out the last batch of flows")

            // write out the data
            toStorageWriter.WriteFlowsToDatabase(timestamp, DBDataChan, isDoneWritingToDBChan)

            // get the data from the individual flow maps
            statsString := ""
            for _, gpcThread := range gpcCaptureThreads {
                gpcThread.SendWriteDBString(timestamp)
                <-gpcThreadIsDoneWritingChan // wait for completion of data creation before continuing
                statsString += gpcThread.GetPcapHandleStats(timestamp)
            }

            // signal that there will be no more data following on the channel
            DBDataChan <- goDB.DBData{}

            // receive on data chan to know that the storage writer function is done
            <-isDoneWritingToDBChan

            // write pcap handle stats to file
            writeToStatsFile(statsString, DBPath+"/"+PcapStatsFilename)

            break
        }
    }

    // de-allocate the memory claimed by the dpi library
    goProbe.DeleteDPI()

    return
}
