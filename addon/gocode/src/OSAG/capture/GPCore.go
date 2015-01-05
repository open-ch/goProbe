////////////////////////////////////////////////////////////////////////////////
//
// GPCore.go
//
// Core process that interacts with all the other interfaces and forwards GPPackets
// from one channel to another. Also responsible for timing database write outs and
// logging information. The Main function is located here.
//
// Written by Lennart Elsen and Fabian Kohn, May 2014
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

    // for error messages not passed through syslog
    "fmt"

    // profiling & system tools
    "os"
    "os/signal"
    "runtime"
    "runtime/debug"

//    "runtime/pprof"

    // own packages
    "OSAG/goProbe"
    "OSAG/goDB"
)

// Fixed configuration parameters ------------------------------------------------
const DB_WRITE_INTERVAL        = 300
const CFG_PATH          string = "/usr/local/goProbe/etc/goprobe.conf"
const SnapLen           int32  = 90
const PromiscMode       bool   = true
const BpfFilterString   string = "not arp and not icmp and not icmp6 and not port 5551"
const DBPath            string = "/usr/local/goProbe/data/db"
const PcapStatsFilename string = "pcap_stats.csv"

// goProbe's main routine --------------------------------------------------------
func main() {

    // CPU Profiling Calls
//    runtime.SetBlockProfileRate(10000000) // PROFILING DEBUG
//    f, proferr := os.Create("GPCore.prof")    // PROFILING DEBUG
//    if proferr != nil {                       // PROFILING DEBUG
//        fmt.Println("Profiling error: "+proferr.Error()) // PROFILING DEBUG
//    } // PROFILING DEBUG
//    pprof.StartCPUProfile(f)     // PROFILING DEBUG
//    defer pprof.StopCPUProfile() // PROFILING DEBUG

    /// LOGGING SETUP ------------------------------------------------------------
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

    /// CHANNEL VARIABLE SETUP ---------------------------------------------------
    // channel for handling writes to the flow map and the database
    gpcThreadIsDoneWritingChan := make(chan bool, 1)
    isDoneWritingToDBChan := make(chan bool, 1)

    // base channel which will be filled with row data from the GPMatrix
    DBDataChan := make(chan goDB.DBData, 1024)

    // channel for handling SIGTERM, SIGINT from the OS
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGUSR1, syscall.SIGUSR2, os.Interrupt)

    /// DB WRITER SETUP ----------------------------------------------------------
    toStorageWriter := goDB.NewDBStorageWrite(DBPath)

    /// CAPTURE ROUTINES MANAGER -------------------------------------------------
    // channel for handling termination signals from the individual
    // interfaces
    gpcThreadTerminatedChan := make(chan string, len(IfaceNames))

    // create capture routine manager
    capManager := goProbe.NewGPCaptureManager(IfaceNames,
                                              SnapLen,
                                              PromiscMode,
                                              BpfFilterString,
                                              gpcThreadTerminatedChan,
                                              DBDataChan,
                                              gpcThreadIsDoneWritingChan,
                                              isDoneWritingToDBChan)

    quitCapFailureMonitorChan := make(chan bool, 1)

    // initialize dpi library
    if dpierr := goProbe.InitDPI(); dpierr != nil {
        goProbe.SysLog.Crit("DPI: " + dpierr.Error())
        return
    }

    // initiate capture routine spawning
    capManager.MonitorFailures(quitCapFailureMonitorChan)
    capManager.StartCapture(DBPath)

    goProbe.SysLog.Debug("Waiting for user signals")

    /// MAIN SELECT FOR WRITE OUT AND PROGRAM TERMINATION ------------------------
    ticker := time.NewTicker(time.Second * time.Duration(DB_WRITE_INTERVAL))
    for {
         select{
         /// TICKER WHICH INITIATES DB WRITING ////
         case t := <-ticker.C:
            goProbe.SysLog.Debug("Initiating flow data flush")

            // take the current timestamp and provide it to each capture thread in order
            // to prepare data
            timestamp := t.Unix()

            // call the data write out routine
            var ifaces []string
            for iface := range capManager.GetActive() {
                ifaces = append(ifaces, iface)
            }
            capManager.WriteDataToDB(ifaces, timestamp,
                                     DBPath + "/" + PcapStatsFilename,
                                     toStorageWriter)

            // recover unavailable interfaces
            capManager.RecoverInactive()

            // call the garbage collectors
            runtime.GC()
            debug.FreeOSMemory()

        /// SIGNAL HANDLING ///
        // read signal from signal channel
        case s := <-sigChan:

            // take the current timestamp and provide it to each capture thread in order
            // to prepare data
            timestamp := time.Now().Unix()

            // if SIGUSER (10) is received, the program should write out a pcap stats report
            // to the stats file, which can be handled by the goprobe.init script
            if s == syscall.SIGUSR1 {

                goProbe.SysLog.Info("Received SIGUSR1 signal: writing out pcap handle stats")

                // get the stats data from the individual maps
                if statsString, err := capManager.GetPcapStats(timestamp); err != nil {
                    goProbe.SysLog.Warning(err.Error())
                } else {
                    // write pcap handle stats to file
                    capManager.WriteToStatsFile(statsString, DBPath+"/"+PcapStatsFilename)
                }

            // reload was called
            } else if s == syscall.SIGUSR2 {
                goProbe.SysLog.Info("Received SIGUSR2 signal: updating configuration")

                // call config parsing and capture routine stop/start
                if err := capManager.UpdateRunning(CFG_PATH); err != nil {
                    goProbe.SysLog.Err("config reload error: "+err.Error())
                }

                // call garbage collector to clean up old activity map
                runtime.GC()
                debug.FreeOSMemory()

            // wait for a termination signal. If it is received, initiate a database flush
            // and terminate the program
            } else if s == syscall.SIGTERM || s == os.Interrupt {
                goProbe.SysLog.Info("Received SIGTERM/SIGINT signal: flushing out the last batch of flows")

                // call the data write out routine
                var ifaces []string
                for iface := range capManager.GetActive() {
                    ifaces = append(ifaces, iface)
                }
                capManager.WriteDataToDB(ifaces, timestamp, DBPath + "/" + PcapStatsFilename, toStorageWriter)

                // terminate the capture routines
                capManager.StopCapturing(ifaces)

                // clean up 
                goProbe.SysLog.Info("Freeing resources and exiting")

                // explicitly call garbage collectors
                runtime.GC()
                debug.FreeOSMemory()

                // stop monitoring capture failures
                quitCapFailureMonitorChan <-true

                // de-allocate the memory claimed by the dpi library
                goProbe.DeleteDPI()

                // close all channels
                close(gpcThreadIsDoneWritingChan)
                close(isDoneWritingToDBChan)
                close(DBDataChan)
                close(sigChan)
                close(gpcThreadTerminatedChan)

                return
            }
        }
    }
}
