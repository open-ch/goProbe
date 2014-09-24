/////////////////////////////////////////////////////////////////////////////////
//
// GPCapture.go
//
// Capturing Interface that deals with spawning the Pcap threads and converting the
// raw packets to the lightweight GPPacket structure
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
    "errors"
    "strconv"

    // packet capturing
    "code.google.com/p/gopacket"
    "code.google.com/p/gopacket/layers"
    "code.google.com/p/gopacket/pcap"

    "sync"

    "OSAG/goDB"
)

var (
    zeroip      []byte = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
    zeroport    []byte = []byte{0x00, 0x00}
    zeropayload []byte = []byte{0x00, 0x00, 0x00, 0x00}
)

type GPCapturer interface {
    CaptureInterface(snapLen int32, promiscMode bool, bpfFilterString string, c chan *GPPacket, iwg sync.WaitGroup)
    GetPcapHandleStats() string
}

type GPCapture struct {
    iface      string
    pcapHandle *pcap.Handle
    stats      *pcap.Stats
    linkType   int

    // flow recording matrix
    flowMat *GPMatrix

    // channels for event handling
    DBDataChan            chan goDB.DBData
    doneWritingSignalChan chan bool
    writeDataSignal       chan int64

    // wait group for go routine synchronization
    wg    sync.WaitGroup
    wgPkt sync.WaitGroup

    // packet counter (for statistics)
    pktsRead uint64
}

func NewGPCapture(iface string, DBDataChan chan goDB.DBData, doneWritingSignalChan chan bool) *GPCapture {
    return &GPCapture{iface,
        nil,
        &pcap.Stats{0, 0, 0},
        0,
        NewGPMatrix(),
        DBDataChan,
        doneWritingSignalChan,
        make(chan int64, 1),
        sync.WaitGroup{},
        sync.WaitGroup{},
        0}
}

// This function gets the interface and configuration parameters from the core
// process and starts handling packets that are captured with gopacket.pcap
func (g *GPCapture) CaptureInterface(snapLen int32, promiscMode bool, bpfFilterString string, threadTerminationChan chan string, iwg *sync.WaitGroup) {
    go func() {
        // generic defer statement if anything goes wrong with the capture thread
        defer func(){
            // output error in case the deferral was triggered by a panic
            if r := recover(); r != nil {
                SysLog.Err(g.iface+": internal capture error")
            }

            // notify the main thread that an error occured so that the interface
            // can be deleted from the list of active interfaces
            threadTerminationChan <- g.iface

        }()

        var (
            err                       error
            packetSource              *gopacket.PacketSource
            numConsecDecodingFailures int
        )

        // open packet stream from an interface
        SysLog.Info(g.iface+": setting up capture")

        // loopback does not support in/out-bound filters, thus ignore it
        if g.iface == "lo" {
            SysLog.Err(g.iface+": interface not suppored")
            iwg.Done()
            return
        }

        g.pcapHandle, err = pcap.OpenLive(g.iface, snapLen, promiscMode, 0)

        // set the BPF filter. This has to be done in order to ensure that the link
        // type is identified correctly
        if e := g.pcapHandle.SetBPFFilter(bpfFilterString); e != nil {
            SysLog.Err(g.iface+": error setting BPF filter: " + e.Error())
            iwg.Done()
            return
        }

        // return from function in case the link type is zero (which can happen if the
        // specified interface does not exist (anymore))
        if g.pcapHandle.LinkType() == layers.LinkTypeNull {
            SysLog.Err(g.iface+": link type is null")
            iwg.Done()
            return
        }

        SysLog.Debug(g.iface+": link type: "+g.pcapHandle.LinkType().String())

        // check whether opening the capture devices actually worked. If not, defer and
        // print out error message
        if err == nil {
            packetSource = gopacket.NewPacketSource(g.pcapHandle, g.pcapHandle.LinkType())

            // set the decoding options to lazy decoding in order to ensure that the packet
            // layers are only decoded once they are needed. Additionally, this is imperative
            // when GRE-encapsulated packets are decoded because otherwise the layers cannot
            // be detected correctly. Additionally set the link type for this interface
            packetSource.DecodeOptions = gopacket.Lazy
            g.linkType                 = int(g.pcapHandle.LinkType())
        } else {
            SysLog.Err(g.iface+": could not open capture: "+err.Error())
            iwg.Done()
            return
        }

        iwg.Done()

        // perform the actual packet capturing:
        for {

            // repeatedly read the packets from the packet source, return an error string
            // if the packet could not be decoded
            if packet, packerr := packetSource.NextPacket(); packerr == nil {
                // wait for the data matrix write out go routine to finish. If the waitGroup
                // counter is non-zero, the go routine blocks here until the counter reaches
                // zero again
                g.wg.Wait()

                g.pktsRead++

                // OSAG gopacket addition: make sure that non-standard encapsulated packets
                // are sliced up correctly. The original gopacket does not support GRE-en-
                // capsulated packets for example
                packet.StripHeaders(g.linkType)

                // pull out the flow-relevant information and write it to the flow matrix.
                // Block the write out thread for the time of the insertion
                if p, perr := g.handlePacket(packet); perr == nil {
                    g.flowMat.addToFlow(p)
                    numConsecDecodingFailures = 0
                } else {
                    numConsecDecodingFailures++

                    // shut down the interface thread if too many consecutive decoding failures
                    // have been encountered
                    if numConsecDecodingFailures > 10000 {
                        SysLog.Err(g.iface+": the last 10 000 packets could not be decoded")
                        return
                    }
                }
            } else {
                SysLog.Warning(g.iface+": interface capture error: " + packerr.Error())
                return
            }
        }
    }()
}

func (g *GPCapture) GetPcapHandleStats(timestamp int64) string {

    pkts     := g.pktsRead
    stats, _ := g.pcapHandle.Stats()

    // CSV format the pcapHandle statistics
    statsString := strconv.FormatInt(timestamp, 10)                   +","+
        g.iface                                                       +","+
        strconv.Itoa(stats.PacketsReceived-g.stats.PacketsReceived)   +","+
        strconv.Itoa(stats.PacketsDropped-g.stats.PacketsDropped)     +","+
        strconv.Itoa(stats.PacketsIfDropped-g.stats.PacketsIfDropped) +","+
        strconv.FormatUint(pkts, 10)                                  +"\n"

    g.stats    = stats
    g.pktsRead = 0

    return statsString
}

// function that takes the raw packet and creates a GPPacket structure from it. Initial sanity
// checking has been done in the function above, so we can now check whether the packet can be
// decoded directly.
func (g *GPCapture) handlePacket(curPack gopacket.Packet) (*GPPacket, error) {

    // process metadata
    var numBytes uint16 = uint16(curPack.Metadata().CaptureInfo.Length)

    // read the direction from which the packet entered the interface
    isInboundTraffic := false
    if curPack.Metadata().CaptureInfo.Inbound == 1 {
        isInboundTraffic = true
    }

    // initialize vars (GO ensures that all variables are initialized with their
    // respective zero element)
    var (
        src, dst      []byte = zeroip, zeroip
        sp, dp        []byte = zeroport, zeroport

        // the default value is reserved by IANA and thus will never occur unless
        // the protocol could not be correctly identified 
        proto         byte   = 0xff
        TCPflags      uint8
        l7payload     []byte = zeropayload
        l7payloadSize uint16

        // size helper vars
        nlHeaderSize uint16
        tpHeaderSize uint16
    )

    // decode rest of packet
    if curPack.NetworkLayer() != nil {

        nlHeaderSize = uint16(len(curPack.NetworkLayer().LayerContents()))

        // get ip info
        ipsrc, ipdst := curPack.NetworkLayer().NetworkFlow().Endpoints()

        src = ipsrc.Raw()
        dst = ipdst.Raw()

        // read out the next layer protocol
        switch curPack.NetworkLayer().LayerType() {
        case layers.LayerTypeIPv4:
             proto = curPack.NetworkLayer().LayerContents()[9]
        case layers.LayerTypeIPv6:
             proto = curPack.NetworkLayer().LayerContents()[6]
        }

        if curPack.TransportLayer() != nil {
            // get port bytes
            psrc, dsrc := curPack.TransportLayer().TransportFlow().Endpoints()

            sp = psrc.Raw()
            dp = dsrc.Raw()

            // if the protocol is TCP, grab the flag information
            if proto == 6 {
                TCPflags = curPack.TransportLayer().LayerContents()[13] // we are primarily interested in SYN, ACK and FIN
            }

            tpHeaderSize = uint16(len(curPack.TransportLayer().LayerContents()))

            // grab the next layer payload's first 4 bytes and calculate
            // the layer 7 payload size if the application layer could
            // be correctly decoded
            if curPack.ApplicationLayer() != nil {
                pl := curPack.ApplicationLayer().Payload()
                lenPayload := len(pl)

                if lenPayload >= 4 {
                    l7payload = pl[0:4]
                } else {
                    for i := 0; i < lenPayload; i++ {
                        l7payload[i] = pl[i]
                    }
                }

            }
            l7payloadSize = numBytes - tpHeaderSize - nlHeaderSize
        }
    } else {
        return nil, errors.New("network layer decoding failed")
    }

    return NewGPPacket(src, dst, sp, dp, l7payload, l7payloadSize, proto, numBytes, TCPflags, isInboundTraffic), nil
}

// function to initiate the flow matrix write out
func (g *GPCapture) SendWriteDBString(timestamp int64) {
    var flowMatToWrite *GPMatrix

    // increment waitGroup counter in order to temporarily block the next packet
    // routine in the capture thread
    g.wg.Add(1)

    // create local wait group passed to GPMatrix in order to ensure that the
    // matrix pointer is not changed while it is still being written
    var wgMatrix sync.WaitGroup
    wgMatrix.Add(1)

    newMatrix := NewGPMatrix()

    // pass newMatrix to the current flow matrix in order to transfer over the flow
    flowMatToWrite = g.flowMat
    flowMatToWrite.prepareDataWrite(timestamp, g.DBDataChan, g.doneWritingSignalChan, g.iface, newMatrix, &wgMatrix)

    // wait for the data write to finish
    wgMatrix.Wait()

    // detach the current GPMatrix by storing the pointer of the original matrix.
    // Attach new matrix as the currently active matrix
    g.flowMat = newMatrix

    // decrement the waitGroup counter in order to continue packet capturing
    g.wg.Done()
}
