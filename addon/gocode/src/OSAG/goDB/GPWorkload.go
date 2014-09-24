/////////////////////////////////////////////////////////////////////////////////
//
// GPWorkload.go
//
// Main workload distribution module deciding  which files in the go database 
// have to be written to or read from
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
package goDB

import (
    "errors"
    "os"
    "strconv"
    "io/ioutil"
)

const EPOCH_DAY int64 = 86400       // one day in seconds
const DB_WRITE_INTERVAL int64 = 300 // write out interval of capture probe

type GPWorkloader interface {
    WriteAttribute(attribute string, data []byte, curTstamp int64, compressionLevel int, errChan chan error)
    CreateWorkerJobs(tfirst int64, tlast int64)
}

type DBWorker struct {
    work_dir string
    load     []int64
}

type GPWorkload struct {
    dbPath  string
    workers []DBWorker
}

func NewGPWorkload(path string) (*GPWorkload, error) {
    // whenever a new workload is created the logging facility is set up
    if err := InitDBLog(); err != nil {
        return nil, err
    }

    return &GPWorkload{path, []DBWorker{}}, nil
}

// make number of workers available to the outside world for loop bounds etc.
func (w *GPWorkload) GetNumWorkers() int {
    return len(w.workers)
}

func (w *GPWorkload) getFileWriter(attribute string, curTstamp int64) (*GPFile, error) {
    var (
        dirTstamp string
        err       error
    )

    // find out if the daily directory already exists, otherwise create it
    dirTstamp = strconv.FormatInt(curTstamp-(curTstamp%EPOCH_DAY), 10)

    if err = os.MkdirAll(w.dbPath+"/"+dirTstamp, 0755); err != nil {
        return nil, errors.New("could not create daily directory: " + err.Error())
    }

    fName := w.dbPath + "/" + dirTstamp + "/" + attribute + ".gpf"

    // call the constructor in GPFile
    return NewGPFile(fName)
}

func (w *GPWorkload) WriteAttribute(attribute string, data []byte, curTstamp int64, compressionLevel int, errChan chan error) {
    go func() {
        defer func(){
            if r:=recover(); r != nil {
                errChan <- errors.New("Internal writer error")
            }
        }()

        // get a file writer
        if writer, err := w.getFileWriter(attribute, curTstamp); err == nil {
            // write block of data and return nil error
            errChan <- writer.WriteTimedBlock(curTstamp, data, compressionLevel)

            // close the file when done writing
            writer.Close()
        } else {
            errChan <- err
        }
    }()
}

func (w *GPWorkload) CreateWorkerJobs(tfirst int64, tlast int64) error {
    // Get list of files in directory
    var dirList []os.FileInfo
    var err error

    if dirList, err = ioutil.ReadDir(w.dbPath); err != nil {
        return err
    }

    // loop over directory list in order to create the timestamp pairs
    var (
        info_file *GPFile
        dir_name  string
    )

    // make sure to start with zero workers as the number of assigned
    // workers depends on how many directories have to be read
    numDirs := 0
    for _, file := range dirList {
        if file.IsDir() && (file.Name() != "./" || file.Name() != "../") {
            dir_name = file.Name()
            temp_dir_tstamp, _ := strconv.ParseInt(dir_name, 10, 64)

            // check if the directory is within time frame of interest
            if tfirst < temp_dir_tstamp+EPOCH_DAY && temp_dir_tstamp < tlast+DB_WRITE_INTERVAL {
                numDirs++

                // create new worker for the directory
                worker := DBWorker{dir_name, []int64{}}

                // retrieve all the relevant timestamps from one of the database files.
                if info_file, err = NewGPFile(w.dbPath + "/" + dir_name + "/bytes_rcvd.gpf"); err != nil {
                    return errors.New("could not read file: " + w.dbPath + "/" + dir_name + "/bytes_rcvd.gpf")
                }

                // add the relevant timestamps to the worker's list
                for _, stamp := range info_file.GetTimestamps() {
                    if stamp != 0 && tfirst < stamp+DB_WRITE_INTERVAL && stamp < tlast {
                        worker.load = append(worker.load, stamp)
                    }
                }
                info_file.Close()

                w.workers = append(w.workers, worker)

            }
        }
    }

    // if the created list is empty for some reason, return an error
    if len(w.workers) == 0 {
        return errors.New("joblist is empty")
    }

    return err
}

func (w *GPWorkload) ExecuteWorkerReadJobs(queryType string, conds []Condition, mapChan chan map[Key]*Val, quitChan chan bool) {

    // start the workers
    for _, worker := range w.workers {
        query := NewQuery(queryType, conds, mapChan, quitChan)
        go w.readBlocksAndEvaluate(worker, query)
    }

    //  SysLog.Debug("spawned "+strconv.Itoa(len(w.workers))+" DB workers")
}

// this is where the actual reading and aggregation magic happens
func (w *GPWorkload) readBlocksAndEvaluate(worker DBWorker, query *Query) {

    var (
        err                                error
        bytesR, bytesS, pktsR, pktsS       []byte
        br_file, bs_file, pr_file, ps_file *GPFile
    )

    cur_dir := worker.work_dir

    numConds         := len(query.Conditions)
    numAttr          := len(query.Attributes)

    condsAvailable   := (numConds != 0)
    condIsQueryAttr  := make([]bool, numConds)

    condBlockBytes   := make([][]byte, numConds)
    condFilePointers := make([]*GPFile, numConds)

    attrBlockBytes   := make([][]byte, numAttr)
    attrFilePointers := make([]*GPFile, numAttr)

    // load the files holding the flow counter variables
    br_file, _ = NewGPFile(w.dbPath + "/" + cur_dir + "/bytes_rcvd.gpf")
    bs_file, _ = NewGPFile(w.dbPath + "/" + cur_dir + "/bytes_sent.gpf")
    pr_file, _ = NewGPFile(w.dbPath + "/" + cur_dir + "/pkts_rcvd.gpf")
    ps_file, _ = NewGPFile(w.dbPath + "/" + cur_dir + "/pkts_sent.gpf")

    // conditionally load the files needed for querying
    for ind := range query.Attributes {
        attrFilePointers[ind], _ = NewGPFile(w.dbPath + "/" + cur_dir + "/" + query.Attributes[ind].Name + ".gpf")
    }

    if condsAvailable {
        for cnd, cond := range query.Conditions {
            for _, attr := range query.Attributes {
                condIsQueryAttr[cnd] = (cond.Attribute == attr.Name)
            }

            if !condIsQueryAttr[cnd] {
                condFilePointers[cnd], _ = NewGPFile(w.dbPath + "/" + cur_dir + "/" + cond.Attribute + ".gpf")
            }
        }
    }

    for b, cur_tstamp := range worker.load {
        // create the map in which the worker will store the aggregations
        query.ResultMap = make(map[Key]*Val)

        // load the values from the counter files based on the timestamp
        if bytesR, err = br_file.ReadTimedBlock(cur_tstamp); err != nil {
            SysLog.Err("[D " + cur_dir + "] Failed to read bytes_rcvd.gpf: " + err.Error())
            query.QuitChan <- true
            return
        }
        if bytesS, err = bs_file.ReadTimedBlock(cur_tstamp); err != nil {
            SysLog.Err("[D " + cur_dir + "] Failed to read bytes_sent.gpf: " + err.Error())
            query.QuitChan <- true
            return
        }
        if pktsR, err = pr_file.ReadTimedBlock(cur_tstamp); err != nil {
            SysLog.Err("[D " + cur_dir + "] Failed to read pkts_rcvd.gpf: " + err.Error())
            query.QuitChan <- true
            return
        }
        if pktsS, err = ps_file.ReadTimedBlock(cur_tstamp); err != nil {
            SysLog.Err("[D " + cur_dir + "] Failed to read pkts_sent.gpf: " + err.Error())
            query.QuitChan <- true
            return
        }

        // sanity check whether block timestamp and header timestamp match
        br_block_tstamp := PutInt64(bytesR[0:8])

        if cur_tstamp != br_block_tstamp {
            SysLog.Err("[Bl " + strconv.Itoa(b) + "] Mismatch between timestamp in header [" + strconv.FormatInt(cur_tstamp, 10) + "] and in block [" + strconv.FormatInt(br_block_tstamp, 10) + "]\n")
            query.QuitChan <- true
            return
        }

        // get the rest of the timestamps in the other files to see whether they are equivalent
        bs_block_tstamp := PutInt64(bytesS[0:8])
        pr_block_tstamp := PutInt64(pktsR[0:8])
        ps_block_tstamp := PutInt64(pktsS[0:8])

        if !((br_block_tstamp == bs_block_tstamp) &&
               (pr_block_tstamp == bs_block_tstamp) &&
               (pr_block_tstamp == ps_block_tstamp)) {
            SysLog.Err("Mismatch between file block timestamps")
            query.QuitChan <- true
            return
        }

        var (
            num_entries int   = int((len(bytesR) - 16) / 8)
            positions   []int = make([]int, numAttr)
            pos_8b      int   = 8

            temp_bytesR, temp_bytesS, temp_pktsR, temp_pktsS uint64
        )

        // read in the attribute data
        for ind := range query.Attributes {
            if attrBlockBytes[ind], err = attrFilePointers[ind].ReadTimedBlock(cur_tstamp); err != nil {
                SysLog.Err("[D " + cur_dir + "] Failed to read " + query.Attributes[ind].Name + ".gpf: " + err.Error())
                query.QuitChan <- true
                return
            }

            // initialize the positions inside the block
            positions[ind] = 8
        }

        // read in the condition values
        if condsAvailable {
            var cond_positions []int = make([]int, numConds)

            for ind := range query.Conditions {
                if condIsQueryAttr[ind] {
                    for aind := range query.Attributes {
                        if query.Attributes[aind].Name == query.Conditions[ind].Attribute {
                            condBlockBytes[ind] = attrBlockBytes[aind]
                        }
                    }
                } else {
                    if condBlockBytes[ind], err = condFilePointers[ind].ReadTimedBlock(cur_tstamp); err != nil {
                        SysLog.Err("[D " + cur_dir + "] Failed to read " + query.Conditions[ind].Attribute + ".gpf: " + err.Error())
                        query.QuitChan <- true
                        return
                    }
                }

                // initialize positions
                cond_positions[ind] = 8
            }

            // aggregate results
            for i := 0; i < num_entries; i++ {
                tempkey := Key{}

                for ind := range query.Attributes {
                    positions[ind] = query.Attributes[ind].CopyRowBytesToKey(attrBlockBytes[ind], positions[ind], &tempkey)
                }

                temp_bytesR = PutUint64(bytesR[pos_8b : pos_8b+8])
                temp_bytesS = PutUint64(bytesS[pos_8b : pos_8b+8])
                temp_pktsR = PutUint64(pktsR[pos_8b : pos_8b+8])
                temp_pktsS = PutUint64(pktsS[pos_8b : pos_8b+8])

                pos_8b += 8

                var condsMet bool = true
                var colValue []byte
                for ind := range query.Conditions {
                    colValue, cond_positions[ind] = query.Conditions[ind].ReadColVal(condBlockBytes[ind], cond_positions[ind])
                    condsMet = condsMet && query.Conditions[ind].Compare(query.Conditions[ind].CondValue, colValue)
                }

                if condsMet {
                    if toUpdate, exists := query.ResultMap[tempkey]; exists {
                        toUpdate.NBytesRcvd += temp_bytesR
                        toUpdate.NBytesSent += temp_bytesS
                        toUpdate.NPktsRcvd += temp_pktsR
                        toUpdate.NPktsSent += temp_pktsS
                    } else {
                        query.ResultMap[tempkey] = &Val{temp_bytesR, temp_bytesS, temp_pktsR, temp_pktsS}
                    }

                }
            }
        } else {
            // aggregate results
            for i := 0; i < num_entries; i++ {
                tempkey := Key{}

                for ind := range query.Attributes {
                    positions[ind] = query.Attributes[ind].CopyRowBytesToKey(attrBlockBytes[ind], positions[ind], &tempkey)
                }

                temp_bytesR = PutUint64(bytesR[pos_8b : pos_8b+8])
                temp_bytesS = PutUint64(bytesS[pos_8b : pos_8b+8])
                temp_pktsR = PutUint64(pktsR[pos_8b : pos_8b+8])
                temp_pktsS = PutUint64(pktsS[pos_8b : pos_8b+8])

                pos_8b += 8

                if toUpdate, exists := query.ResultMap[tempkey]; exists {
                    toUpdate.NBytesRcvd += temp_bytesR
                    toUpdate.NBytesSent += temp_bytesS
                    toUpdate.NPktsRcvd += temp_pktsR
                    toUpdate.NPktsSent += temp_pktsS
                } else {
                    query.ResultMap[tempkey] = &Val{temp_bytesR, temp_bytesS, temp_pktsR, temp_pktsS}
                }
            }
        }

        // push the aggregated map onto the map channel after each completed
        // task in the job list
        query.MapChan <- query.ResultMap

    }

    // signal that the current worker is done
    query.QuitChan <- true

}
