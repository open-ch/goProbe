/////////////////////////////////////////////////////////////////////////////////
//
// GPMatrix.go
//
// Datastructure storing the individual flows. Responsible for updating the Flow
// information and writing it to the database
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
package goProbe

import (
    "sync"
    "OSAG/goDB"
)

/// BORROWED FROM GOOGLE ///
// Convert i to hexadecimal string.
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
/// END GOOGLE ///

type Key struct {
    sip        [16]byte
    dip        [16]byte
    dport      [2]byte
    l7proto    [2]byte
    proto      uint8
}

type Val struct {
    nBytesRcvd uint64
    nBytesSent uint64
    nPktsRcvd  uint64
    nPktsSent  uint64
}

type GPMatrix struct {
    flowMap           map[EPHash]*GPFlow
}

// Constructor
func NewGPMatrix() *GPMatrix {
    return &GPMatrix{make(map[EPHash]*GPFlow)}
}

// This function is mainly there to read the GPPackets from the channel it
// was given and creating the relevant flow structures that are inserted
// to or updated in the map
func (m *GPMatrix) addToFlow(packet *GPPacket) {

    // update or assign the flow
    if flowToUpdate, existsHash := m.flowMap[packet.epHash]; existsHash {
        flowToUpdate.UpdateFlow(packet)
    } else if flowToUpdate, existsReverseHash := m.flowMap[packet.epHashReverse]; existsReverseHash {
        flowToUpdate.UpdateFlow(packet)
    } else {
        m.flowMap[packet.epHash] = NewGPFlow(packet)
    }
}

/// PRIVATE METHODS ///
// Write the data stored in the matrix to the database or to the specified file
func (m *GPMatrix) prepareDataWrite(timestamp int64, DBDataChan chan goDB.DBData, doneWriting chan bool, iface string, newMatrix *GPMatrix, wg *sync.WaitGroup) {
    go func() {

        var dataAgg map[Key]*Val

        // check if there was even any data recorded for the given interfaces
        if len(m.flowMap) > 0 {
            // aggregate source port information and fill in the flows worth
            // keeping
            dataAgg = m.preAggregateSourcePort(newMatrix)

            // prepare the aggregated flow data for the storage writer
            m.prepareFlows(dataAgg, timestamp, DBDataChan, iface)
        } else {
            SysLog.Debug("There are currently no flow records available")
        }

        // signal that writing is done
        doneWriting <- true

        // delete pre-aggregate
        dataAgg   = nil

        // decrement wait group counter so that the capture thread knows
        // that it may continue
        wg.Done()
    }()
}

func (m *GPMatrix) preAggregateSourcePort(newMatrix *GPMatrix) map[Key]*Val {

    hits := make(map[Key]*Val)

    for k, v := range m.flowMap {

        // check if the flow actually has any interesting information for us
        if !(v.HasBeenIdle()) {
            var(
                tsip, tdip [16]byte
            )

            copy(tsip[:], v.endpoint.sip)
            copy(tdip[:], v.endpoint.dip)

            var tempkey = Key{tsip, tdip,
                [2]byte{v.endpoint.dport[0], v.endpoint.dport[1]},
                [2]byte{uint8(v.l7proto>>8), uint8(v.l7proto&0xff)},
                v.endpoint.protocol}

            if toUpdate, exists := hits[tempkey]; exists {
                toUpdate.nBytesRcvd += v.nBytesRcvd
                toUpdate.nBytesSent += v.nBytesSent
                toUpdate.nPktsRcvd  += v.nPktsRcvd
                toUpdate.nPktsSent  += v.nPktsSent
            } else {
                hits[tempkey] = &Val{v.nBytesRcvd, v.nBytesSent, v.nPktsRcvd, v.nPktsSent}
            }

            // check whether the flow should be retained for the next interval
            // or thrown away
            if v.IsWorthKeeping() {

                // reset and insert the flow into the new flow matrix
                v.Reset()
                newMatrix.flowMap[k] = v
            }
        }
    }

    return hits
}


// convert the flows in the map to individual row strings and push them
// on the channel
func (m *GPMatrix) prepareFlows(dataAgg map[Key]*Val, timestamp int64, DBDataChan chan goDB.DBData, iface string) {

    dbData := goDB.DBData{[]byte{}, []byte{}, []byte{},
        []byte{}, []byte{}, []byte{},
        []byte{}, []byte{}, []byte{},
        timestamp, iface}

    var tstampArr = []byte{uint8(timestamp>>56),
        uint8(timestamp>>48),
        uint8(timestamp>>40),
        uint8(timestamp>>32),
        uint8(timestamp>>24),
        uint8(timestamp>>16),
        uint8(timestamp>>8),
        uint8(timestamp&0xff)}

    // push preamble to the arrays
    dbData.Bytes_rcvd = append(dbData.Bytes_rcvd, tstampArr...)
    dbData.Bytes_sent = append(dbData.Bytes_sent, tstampArr...)
    dbData.Pkts_rcvd  = append(dbData.Pkts_rcvd,  tstampArr...)
    dbData.Pkts_sent  = append(dbData.Pkts_sent,  tstampArr...)

    dbData.Dip        = append(dbData.Dip,        tstampArr...)
    dbData.Sip        = append(dbData.Sip,        tstampArr...)
    dbData.Dport      = append(dbData.Dport,      tstampArr...)
    dbData.L7proto    = append(dbData.L7proto,    tstampArr...)
    dbData.Proto      = append(dbData.Proto,      tstampArr...)

    // loop through the flow map in order to (a) extract the relevant
    // values in order to write them out to the DB and (b) to retain
    // flows with a known layer 7 protocol
    for K, V := range dataAgg {

        // counters
        dbData.Bytes_rcvd = append(dbData.Bytes_rcvd,
            uint8(V.nBytesRcvd>>56),
            uint8(V.nBytesRcvd>>48),
            uint8(V.nBytesRcvd>>40),
            uint8(V.nBytesRcvd>>32),
            uint8(V.nBytesRcvd>>24),
            uint8(V.nBytesRcvd>>16),
            uint8(V.nBytesRcvd>>8),
            uint8(V.nBytesRcvd&0xff))
        dbData.Bytes_sent = append(dbData.Bytes_sent,
            uint8(V.nBytesSent>>56),
            uint8(V.nBytesSent>>48),
            uint8(V.nBytesSent>>40),
            uint8(V.nBytesSent>>32),
            uint8(V.nBytesSent>>24),
            uint8(V.nBytesSent>>16),
            uint8(V.nBytesSent>>8),
            uint8(V.nBytesSent&0xff))
        dbData.Pkts_rcvd  = append(dbData.Pkts_rcvd,
            uint8(V.nPktsRcvd>>56),
            uint8(V.nPktsRcvd>>48),
            uint8(V.nPktsRcvd>>40),
            uint8(V.nPktsRcvd>>32),
            uint8(V.nPktsRcvd>>24),
            uint8(V.nPktsRcvd>>16),
            uint8(V.nPktsRcvd>>8),
            uint8(V.nPktsRcvd&0xff))
        dbData.Pkts_sent  = append(dbData.Pkts_sent,
            uint8(V.nPktsSent>>56),
            uint8(V.nPktsSent>>48),
            uint8(V.nPktsSent>>40),
            uint8(V.nPktsSent>>32),
            uint8(V.nPktsSent>>24),
            uint8(V.nPktsSent>>16),
            uint8(V.nPktsSent>>8),
            uint8(V.nPktsSent&0xff))

        // attributes
        dbData.Dip     = append(dbData.Dip,     K.dip[0], K.dip[1], K.dip[2],  K.dip[3],  K.dip[4],  K.dip[5],  K.dip[6],  K.dip[7],
                                                K.dip[8], K.dip[9], K.dip[10], K.dip[11], K.dip[12], K.dip[13], K.dip[14], K.dip[15])
        dbData.Sip     = append(dbData.Sip,     K.sip[0], K.sip[1], K.sip[2],  K.sip[3],  K.sip[4],  K.sip[5],  K.sip[6],  K.sip[7],
                                                K.sip[8], K.sip[9], K.sip[10], K.sip[11], K.sip[12], K.sip[13], K.sip[14], K.sip[15])
        dbData.Dport   = append(dbData.Dport,   K.dport[0], K.dport[1])
        dbData.L7proto = append(dbData.L7proto, K.l7proto[0], K.l7proto[1])
        dbData.Proto   = append(dbData.Proto,   K.proto)
    }

    // push postamble to the arrays
    dbData.Bytes_rcvd = append(dbData.Bytes_rcvd,   tstampArr...)
    dbData.Bytes_sent = append(dbData.Bytes_sent,   tstampArr...)
    dbData.Pkts_rcvd  = append(dbData.Pkts_rcvd,    tstampArr...)
    dbData.Pkts_sent  = append(dbData.Pkts_sent,    tstampArr...)

    dbData.Dip        = append(dbData.Dip,          tstampArr...)
    dbData.Sip        = append(dbData.Sip,          tstampArr...)
    dbData.Dport      = append(dbData.Dport,        tstampArr...)
    dbData.L7proto    = append(dbData.L7proto,      tstampArr...)
    dbData.Proto      = append(dbData.Proto,        tstampArr...)

    // push the final struct on to the channel
    DBDataChan <- dbData
}

// convert the ip byte arrays to string. The formatting logic for IPv6
// is directly copied over from the go IP package in order to save an
// additional import just for string operations
func rawIpToString(ip []byte) string {
    var(
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
            itod(uint(ip[1]))    + "." +
            itod(uint(ip[2]))    + "." +
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
