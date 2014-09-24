/////////////////////////////////////////////////////////////////////////////////
//
// GPStorageWriter.go
//
// Interface for handling all interactions with a database or files. Data will be
// written out from this point
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
    "time"
    "strconv"
)

const COMPRESSION_LEVEL int = 512
const NUM_COLS          int = 9

type DBStorageWrite struct {
    // writing to file
    dbPath       string
}

func NewDBStorageWrite(dbPath string) *DBStorageWrite {
    return &DBStorageWrite{dbPath}
}

func (w *DBStorageWrite) WriteFlowsToDatabase(timestamp int64, DBDataChan chan DBData, doneWritingChan chan bool) {
    go func() {
        // for as long as there is data on the channel, fill the buffer and write it out
        // once it reaches its capacity. If there is no more data on the channel, write
        // it out and return
        tStart := time.Now()

        // explicitly initialize database log
        var logErr error
        if logErr = InitDBLog(); logErr != nil{
            doneWritingChan <- true
            return
        }

        var(
            dataAgg      DBData
            attributes = [NUM_COLS]string{"bytes_rcvd", "bytes_sent",
                                           "pkts_rcvd", "pkts_sent",
                                           "dip","sip",
                                           "proto","l7proto", "dport"}
            num_entries int    = 0
        )

        for {
            // get current data row string from channel
            dataAgg = <-DBDataChan

            // check if there is still data for us on the channel
            if len(dataAgg.Proto) == 0 {
                break
            }

            var(
                dbPath    string     = w.dbPath+"/"+dataAgg.Iface
                dataItems [][]byte   = make([][]byte, NUM_COLS)
            )

            dataItems[0] = dataAgg.Bytes_rcvd
            dataItems[1] = dataAgg.Bytes_sent
            dataItems[2] = dataAgg.Pkts_rcvd
            dataItems[3] = dataAgg.Pkts_sent
            dataItems[4] = dataAgg.Dip
            dataItems[5] = dataAgg.Sip
            dataItems[6] = dataAgg.Proto
            dataItems[7] = dataAgg.L7proto
            dataItems[8] = dataAgg.Dport

            // create workload that handles the write operations
            var workload *GPWorkload
            if workload, logErr = NewGPWorkload(dbPath); logErr != nil {
                doneWritingChan <- true
                return
            }

            errChan  := make(chan error)

            // loop over attributes and concurrently write them to their respective files
            for i:=0; i<NUM_COLS; i++{
                workload.WriteAttribute(attributes[i], dataItems[i], dataAgg.Tstamp, COMPRESSION_LEVEL, errChan)
            }

            // loop over channel to check if any writer returned an error
            for k:=0; k<NUM_COLS; k++{

                // if there was an error, quit writing to the database and return
                if e:= <-errChan; e != nil{
                    SysLog.Err("Writing to DB failed: "+e.Error())
                    // TODO: implement recovery options here, e.g. rollback all items written with index
                    // smaller than k
                    doneWritingChan <- true
                    return
                }
            }

            num_entries += (len(dataItems[0])-16)/8
        }

        tStop := time.Now()

        // log success message
        SysLog.Debug("Wrote "+strconv.Itoa(num_entries)+" new flow entries to database in "+(tStop.Sub(tStart).String()))

        doneWritingChan <- true
    }()
}
