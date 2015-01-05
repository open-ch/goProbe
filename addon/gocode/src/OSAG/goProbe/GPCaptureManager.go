/////////////////////////////////////////////////////////////////////////////////
//
// GPCaptureManager.go
//
// Wrapper which manages spawning of the capture routines, returning those which are
// running and recovering inactive interfaces
//
// Written by Lennart Elsen and Fabian Kohn, Movember 2014
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
package goProbe

import (
    "sync"
    "time"
    "os"
    "errors"

    "strconv"
    "bufio"
    "strings"

    // goDB
    "OSAG/goDB"
)

// Capture thread settings --------------------------------------------------------
type captureParameters struct {
    snapLength          int32
    promiscMode         bool
    bpf                 string

    // channels for communication with the capture routines
    terminationChan     chan string
    DBDataChan          chan goDB.DBData
    doneWritingChan     chan bool

    // channel for communicating with the database writer
    dbWriterIsDoneChan  chan bool
}

// Interface objects and function specification -----------------------------------
type GPCaptureManagerer interface {
    StartCapture(dbPath string)
    GetActive() map[string]*GPCapture
    MonitorFailures(quitChan chan bool)
    RecoverInactive()
    UpdateRunning(pathToConfig string) error
}

// Maps listing all capture routines and their corresponding activity state --------
type routine struct {
    packetReader *GPCapture
    active       bool
}
type captureRoutines struct {
    sync.RWMutex
    routines map[string]*routine
}

type GPCaptureManager struct {

    capture    captureRoutines
    ifaceList  []string

    isStarting bool

    // capture settings
    capParams  captureParameters
}

// Constructor --------------------------------------------------------------------
func NewGPCaptureManager(ifaceList []string, snapLength int32, promiscMode bool,
                         bpf string, terminationChan chan string,
                         DBDataChan chan goDB.DBData,
                         doneWritingChan chan bool,
                         dbWriterIsDoneChan chan bool) *GPCaptureManager {

    cR := captureRoutines{routines: make(map[string]*routine)}

    // create settings struct
    cP := captureParameters{snapLength, promiscMode, bpf, terminationChan,
                            DBDataChan, doneWritingChan, dbWriterIsDoneChan}

    // assign GPCapture objects for all interfaces and set their initial activity 
    // state to false
    for _, iface := range ifaceList {
        cR.routines[iface] = &routine{NewGPCapture(iface, DBDataChan, doneWritingChan), false}
    }

    // set initial state to starting
    starting := true

    return &GPCaptureManager{cR, ifaceList, starting, cP}
}

// Initial interface spawning -----------------------------------------------------
func(m *GPCaptureManager) StartCapture(dbPath string) {
    go func() {

        // create lockfile so that the init script does not access the pcap_stats
        // file during startup 
        var(
            lockFilePath string = dbPath + "/startup.lock"
            err          error
        )
        if _, err = os.OpenFile(lockFilePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644); err != nil {
            SysLog.Err("Lockfile creation error: "+err.Error())
        }

        var ifaceWG sync.WaitGroup
        l := strconv.Itoa(len(m.capture.routines))
        started := 0

        // fire up the capture routines
        for iface, _ := range m.capture.routines {
            m.capture.Lock()
            m.captureOnIface(iface, &ifaceWG)
            m.capture.Unlock()

            started++
            SysLog.Info(strconv.Itoa(started)+"/"+l+" routines started")
        }

        // delete the lock file
        if rmerr := os.Remove(lockFilePath); rmerr != nil {
            SysLog.Err("Lockfile removal error: "+rmerr.Error())
        }

        SysLog.Info("Capture setup complete")

        // signal that initial capture set up has been completed
        m.isStarting = false
    }()
}

// Interface capture routine termination ------------------------------------------
func(m *GPCaptureManager) StopCapturing(ifaces []string) {

    if len(ifaces) == 0 {
        return
    }

    // make channel to wait for quit acknowledgement
    ackChan := make(chan string, len(ifaces))

    m.capture.RLock()
    for _, iface := range ifaces {
        if capRoutine, exists := m.capture.routines[iface]; exists {
            if capRoutine.packetReader == nil {
                SysLog.Warning("capture termination: attempted to shutdown <nil> capture routine")
            }

            // tell capture routine to terminate itself
            go capRoutine.packetReader.InitiateTermination(ackChan)
        }
    }
    m.capture.RUnlock()

    // empty channel to see if all acks came back
    m.capture.Lock()
    for i:=0; i<len(ifaces); i++ {
        iface := <-ackChan
        SysLog.Info("Capture routine on '"+iface+"' quit")
        m.capture.routines[iface].active = false
    }
    m.capture.Unlock()
    close(ackChan)
}

// Capture routine data write out -------------------------------------------------
func(m *GPCaptureManager) WriteDataToDB(ifaces []string, tstamp int64,
                                        pathToStatsFile string,
                                        storageWriter *goDB.DBStorageWrite) {

    // initiate write out of data
    storageWriter.WriteFlowsToDatabase(tstamp, m.capParams.DBDataChan, m.capParams.dbWriterIsDoneChan)

    // tell capture routines to send the data to the storage writer
    statsString := ""
    for _, iface := range ifaces {
        m.capture.RLock()
        if capRoutine, exists := m.capture.routines[iface]; exists && m.capture.routines[iface].active {
            if capRoutine.packetReader == nil {
                SysLog.Warning("data writeout: attempted write from  <nil> capture routine")
                m.capture.RUnlock()
                continue
            }
            capRoutine.packetReader.SendWriteDBString(tstamp)
            <-m.capParams.doneWritingChan
            statsString += capRoutine.packetReader.GetPcapHandleStats(tstamp)
            SysLog.Debug(iface+" is done writing")
        }
        m.capture.RUnlock()
    }

    // signal that there will be no more data following on the channel
    m.capParams.DBDataChan <-goDB.DBData{}
    <-m.capParams.dbWriterIsDoneChan

    // write pcap handle stats
    if statsString != "" {
        m.WriteToStatsFile(statsString, pathToStatsFile)
    }
}

// Routine which handles the stats write out --------------------------------------
func(m *GPCaptureManager) GetPcapStats(timestamp int64) (string, error) {
    statsString := ""

    // get the pcap handle stats from the individual capture routines
    for _, gpcThread := range m.GetActive() {
        if gpcThread.packetReader == nil {
            SysLog.Warning("pcap stats writeout: attempt to access <nil> capture routine")
            continue
        }
        statsString += gpcThread.packetReader.GetPcapHandleStats(timestamp)
    }

    if statsString == "" {
        return statsString, errors.New("could not retrieve pcap stats from any interface")
    }

    return statsString, nil
}

func(m *GPCaptureManager) WriteToStatsFile(data string, pathToFile string) {
    // open stats file for writing and write column descriptions in there
    var (
        err             error
        statsFileHandle *os.File
    )

    if statsFileHandle, err = os.OpenFile(pathToFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644); err != nil {
        SysLog.Err("Opening file " + pathToFile + " failed: " + err.Error())
    }

    // header of csv file: "pkts_rcvd,iface,pkts_dropped,pkts_if_dropped"
    if _, wrerr := statsFileHandle.WriteString(data); wrerr != nil {
        SysLog.Err("Writing data to " + pathToFile + " failed: " + err.Error())
    }

    // close the file
    statsFileHandle.Close()
}


// Function returning all live capturing instances to the main routine ------------
func(m *GPCaptureManager) GetActive() map[string]*routine {

    active := make(map[string]*routine)

    m.capture.RLock()
    defer m.capture.RUnlock()

    // get all capture routines with state active
    for iface, routine := range m.capture.routines {
        if routine.active {
            active[iface] = m.capture.routines[iface]
        }
    }

    return active
}

// Failure monitoring and recovery functions --------------------------------------
func(m *GPCaptureManager) MonitorFailures(quitChan chan bool) {
    go func(){
        // continuously read from the termination channel to determine which
        // interface failed
        for {
            select {
            case iface := <-m.capParams.terminationChan:
                SysLog.Warning("Capture on '"+iface+"' terminated. Listing it as inactive")

                // remove the packet reader object and set activity state to false 
                m.capture.Lock()
                m.capture.routines[iface] = &routine{nil, false}
                m.capture.Unlock()

            case <-quitChan:
                return
            }
        }
    }()
}

func(m *GPCaptureManager) RecoverInactive() {
    go func(){
        // do nothing if all interfaces are up or if the capture routines are still starting 
        if m.areMapsEqual(m.GetActive()) || m.isStarting {
            return
        }

        var(
            ifaceWG        sync.WaitGroup
            inactiveIfaces string = ""
        )

        // recover all those routines which are listed as inactive in the activity map
        m.capture.Lock()
        defer m.capture.Unlock()

        for iface, capRoutine := range m.capture.routines {
            if !capRoutine.active {
                // create new capture object and start capturing on it
                m.capture.routines[iface] = &routine{NewGPCapture(iface,
                                            m.capParams.DBDataChan,
                                            m.capParams.doneWritingChan), false}

                m.captureOnIface(iface, &ifaceWG)
                inactiveIfaces += iface + ","
            }
        }

        inactiveIfaces = inactiveIfaces[:len(inactiveIfaces)-1]
        SysLog.Info("Attempted recovery of inactive interfaces: "+inactiveIfaces)
    }()
}

// Configuration reloading -------------------------------------------------------
func(m *GPCaptureManager) UpdateRunning(pathToConfig string) error {

    var(
        cfgFile *os.File
        err     error
    )

    // CONFIG PARSING //
    // open configuration file for parsing new list of interfaces
    if cfgFile, err = os.OpenFile(pathToConfig, os.O_RDONLY, 0666); err != nil {
        return err
    }
    defer cfgFile.Close()

    // read from the configuration
    var cfgIfaces []string
    scanner := bufio.NewScanner(cfgFile)

    for scanner.Scan() {
        cfgIfaces = append(cfgIfaces, strings.Split(scanner.Text(), " ")...)
    }

    // check if file is empty
    if len(cfgIfaces) == 0 {
        return errors.New("read empty configuration file")
    }

    // check if scanning was successful
    if scerr := scanner.Err(); err != nil {
        return scerr
    }

    // create updated routines map given the new configuration
    updated := make(map[string]*routine)
    m.capture.RLock()
    for _, iface := range cfgIfaces {
        if iface == " " || iface == "" {
            continue
        }

        if capRoutine, exists := m.capture.routines[iface]; exists {
            updated[iface] = capRoutine
        } else {
            updated[iface] = &routine{nil, false}
        }
    }
    m.capture.RUnlock()

    // ADJUSTMENT OF ACTIVE IFACES
    var obsolete []string

    // make list of interfaces which should no longer be attended to
    m.capture.RLock()
    for iface, _ := range m.capture.routines {
        if _, exists := updated[iface]; !exists {
            obsolete = append(obsolete, iface)
        }
    }
    m.capture.RUnlock()

    // shutdown obsolete routines
    m.StopCapturing(obsolete)

    // replace map of updated interfaces with the current one
    m.capture.Lock()
    m.capture.routines = updated
    m.capture.Unlock()

    // start all inactive interfaces
    m.RecoverInactive()

    return nil
}

// Actual capture spawning/stopping helper routines ------------------------------
func(m *GPCaptureManager) captureOnIface(iface string,
                                         iwg *sync.WaitGroup) {

    // spawn capture
    iwg.Add(1)
    m.capture.routines[iface].packetReader.CaptureInterface(m.capParams.snapLength,
                             m.capParams.promiscMode,
                             m.capParams.bpf,
                             m.capParams.terminationChan,
                             iwg)
    iwg.Wait()

    // tentatively set the routine's state to active
    m.capture.routines[iface].active = true

    // wait some time to allow the previous capturing thread to fire up
    time.Sleep(100 * time.Millisecond)
}

// Helper routine to check map equality -------------------------------------------
func(m *GPCaptureManager) areMapsEqual(active map[string]*routine) bool {
    m.capture.RLock()
    defer m.capture.RUnlock()

    for iface, _ := range m.capture.routines {
        if _, exists := active[iface]; !exists {
            return false
        }
    }

    return true
}
