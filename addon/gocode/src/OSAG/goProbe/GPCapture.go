/////////////////////////////////////////////////////////////////////////////////
//
// GPCapture.go
//
// Capturing Interface that deals with spawning the Pcap threads and converting the
// raw packets to the lightweight GPPacket structure
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
package goProbe

import (
    "errors"
    "strconv"

    // debugging stack traces
    "runtime/debug"
    "fmt"

    // packet capturing
    "code.google.com/p/gopacket"
    "code.google.com/p/gopacket/layers"
    "code.google.com/p/gopacket/pcap"

    // race condition prevention
    "sync"
    "sync/atomic"
    "time"

    // database access
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

type FlowTable struct {
    sync.Mutex
    flows *GPMatrix
}

type GPCapture struct {
    iface      string
    pcapHandle *pcap.Handle
    stats      *pcap.Stats
    linkType   int

    // flow recording matrix
    flowTab    FlowTable

    // channels for event handling
    DBDataChan            chan goDB.DBData
    doneWritingSignalChan chan bool
    writeDataSignal       chan int64

    // packet counter (for statistics)
    pktsRead uint64

    // channel signaling that the capture routine should terminate itself
    quitCaptureChan chan bool
    ackQuitChan     chan bool
    quitting        bool
}

func NewGPCapture(iface string, DBDataChan chan goDB.DBData, doneWritingSignalChan chan bool) *GPCapture {
    return &GPCapture{iface,
        nil,
        &pcap.Stats{0, 0, 0},
        0,
        FlowTable{flows: NewGPMatrix()},
        DBDataChan,
        doneWritingSignalChan,
        make(chan int64, 1),
        0,
        make(chan bool, 1),
        make(chan bool, 1),
        false}
}

// Capturing setup -------------------------------------------------------------------
// capture defer function
func(g *GPCapture) CaptureDefer(terminationChan chan string){

    // close the pcap handle (deallocates underlying resources in libpcap)
    if g.pcapHandle != nil{
        g.pcapHandle.Close()
    }

    // reset all references within the capture routine to nil to enable
    // clean up by garbage collector
    g.pcapHandle, g.stats, g.flowTab.flows = nil, nil, nil

    // generic defer statement if anything goes wrong with the capture thread, 
    // i.e. if it returns for some reason
    if r := recover(); r != nil {

        // fetch stack trace
        trace := string(debug.Stack())

        SysLog.Err(g.iface+": capture error")
        fmt.Println(g.iface+": defer trace\n", r, "\n"+trace)

        // signal that packet reading terminated ungracefully
        terminationChan <-g.iface
        return
    }

    // get the ack from the ack quit channel and pass it to the outer routine
    if g.quitting {
        g.ackQuitChan <-true
        return
    }

    terminationChan <-g.iface
}


// This function gets the interface and configuration parameters from the core process
// and starts handling packets that are captured with gopacket.pcap
func (g *GPCapture) CaptureInterface(snapLen int32, promiscMode bool, bpfFilterString string,
                                     threadTerminationChan chan string,
                                     iwg *sync.WaitGroup) {
    go func() {
        defer g.CaptureDefer(threadTerminationChan)

        var (
            err                       error
            packetSource              *gopacket.PacketSource
        )

        SysLog.Info(g.iface+": setting up capture")

        // loopback does not support in/out-bound filters, thus ignore it
        if g.iface == "lo" {
            SysLog.Err(g.iface+": interface not supported")
            iwg.Done()
            return
        }

        // open packet stream from an interface
        if g.pcapHandle, err = pcap.OpenLive(g.iface, snapLen, promiscMode, 250*time.Millisecond); err != nil {
            SysLog.Err(g.iface+": could not open capture: "+err.Error())
            iwg.Done()
            return
        }

        // set the BPF filter. This has to be done in order to ensure that the link
        // type is identified correctly
        if e := g.pcapHandle.SetBPFFilter(bpfFilterString); e != nil {
            SysLog.Err(g.iface+": error setting BPF filter: " + e.Error())
            iwg.Done()
            return
        }
        SysLog.Debug(g.iface+": bpf set")

        // return from function in case the link type is zero (which can happen if the
        // specified interface does not exist (anymore))
        if g.pcapHandle.LinkType() == layers.LinkTypeNull {
            SysLog.Err(g.iface+": link type is null")
            iwg.Done()
            return
        }

        SysLog.Debug(g.iface+": link type: "+g.pcapHandle.LinkType().String())

        // specify the pcap as the source from which the packets will be read
        packetSource = gopacket.NewPacketSource(g.pcapHandle, g.pcapHandle.LinkType())

        // set the decoding options to lazy decoding in order to ensure that the packet
        // layers are only decoded once they are needed. Additionally, this is imperative
        // when GRE-encapsulated packets are decoded because otherwise the layers cannot
        // be detected correctly. Additionally set the link type for this interface
        packetSource.DecodeOptions = gopacket.Lazy
        g.linkType                 = int(g.pcapHandle.LinkType())

        SysLog.Debug(g.iface+": set packet source")

        iwg.Done()

        // perform the actual packet capturing:
        g.ReadPackets(packetSource)

    }()

}

// Packet reading --------------------------------------------------------------------
func(g *GPCapture) ReadPackets(packetSource *gopacket.PacketSource) {

    var numConsecDecodingFailures int

    SysLog.Debug("Entered Read packets")

    for {
        select {
        case <-g.quitCaptureChan:
            return
        default:
            // repeatedly read the packets from the packet source, return an error string
            // if the packet could not be decoded
            if packet, packerr := packetSource.NextPacket(); packerr == nil {

                // safely increment packet counter
                atomic.AddUint64(&g.pktsRead, 1)

                // OSAG gopacket addition: make sure that non-standard encapsulated packets
                // are sliced up correctly. The original gopacket does not support GRE-en-
                // capsulated packets for example
                packet.StripHeaders(g.linkType)

                // pull out the flow-relevant information and write it to the flow matrix.
                // Block the write out thread for the time of the insertion
                if p, perr := g.handlePacket(packet); perr == nil {

                    // protect critical section
                    g.flowTab.Lock()
                    g.flowTab.flows.addToFlow(p)
                    g.flowTab.Unlock()

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
            } else if packerr == pcap.NextErrorTimeoutExpired {
                continue
            } else {
                SysLog.Warning(g.iface+": interface capture error: " + packerr.Error())
                return
            }
        }
    }
}

// Packet information digestion ------------------------------------------------------
// function that takes the raw packet and creates a GPPacket structure from it. Initial
//  sanity checking has been performed in the function above, so we can now check whether
// the packet can be decoded directly
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
        fragBits      byte   = 0x00
        fragOffset    uint16
        TCPflags      uint8
        l7payload     []byte = zeropayload
        l7payloadSize uint16

        // size helper vars
        nlHeaderSize uint16
        tpHeaderSize uint16
    )

    // decode rest of packet
    if curPack.NetworkLayer() != nil {

	    nw_l := curPack.NetworkLayer().LayerContents()
        nlHeaderSize = uint16(len(nw_l))

        // exit if layer is available but the bytes aren't captured by the layer
        // contents
        if nlHeaderSize == 0 {
            return nil, errors.New("Network layer header not available")
        }

        // get ip info
        ipsrc, ipdst := curPack.NetworkLayer().NetworkFlow().Endpoints()

        src = ipsrc.Raw()
        dst = ipdst.Raw()

        // read out the next layer protocol
        switch curPack.NetworkLayer().LayerType() {
        case layers.LayerTypeIPv4:

            proto = nw_l[9]

	        // check for IP fragmentation
	        fragBits   = (0xe0 & nw_l[6]) >> 5
	        fragOffset = (uint16(0x1f & nw_l[6]) << 8) | uint16(nw_l[7])

	        // return decoding error if the packet carries anything other than the
	        // first fragment, i.e. if the packet lacks a transport layer header
	        if fragOffset != 0 {
                return nil, errors.New("Fragmented IP packet: offset: "+strconv.FormatUint(uint64(fragOffset), 10)+" flags: "+strconv.FormatUint(uint64(fragBits), 10))
	        }

        case layers.LayerTypeIPv6:
             proto = nw_l[6]
        }

        if curPack.TransportLayer() != nil {

            // get layer contents
            tp_l := curPack.TransportLayer().LayerContents()
            tpHeaderSize = uint16(len(tp_l))

            if tpHeaderSize == 0  {
                return nil, errors.New("Transport layer header not available")
            }

            // get port bytes
            psrc, dsrc := curPack.TransportLayer().TransportFlow().Endpoints()

            // only get raw bytes if we actually have TCP or UDP
            if proto == 6 || proto == 17 {
                sp = psrc.Raw()
                dp = dsrc.Raw()
            }

            // if the protocol is TCP, grab the flag information
            if proto == 6 {
                if tpHeaderSize < 14  {
                    return nil, errors.New("Incomplete TCP header: "+string(tp_l))
                }

                TCPflags = tp_l[13] // we are primarily interested in SYN, ACK and FIN
            }

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

// Database writeout and stats handling ----------------------------------------------
// function to initiate the flow matrix write out
func (g *GPCapture) SendWriteDBString(timestamp int64) {

    // create local wait group passed to GPMatrix in order to ensure that the
    // matrix pointer is not changed while it is still being written
    var wgMatrix sync.WaitGroup

    newMatrix := NewGPMatrix()
    wgMatrix.Add(1)

    // pass newMatrix to the current flow matrix in order to transfer over the flow
    g.flowTab.Lock()
    g.flowTab.flows.prepareDataWrite(timestamp, g.DBDataChan, g.doneWritingSignalChan, g.iface, newMatrix, &wgMatrix)

    // wait for the data write to finish
    wgMatrix.Wait()

    // detach the current GPMatrix by storing the pointer of the original matrix.
    // Attach new matrix as the currently active matrix
    g.flowTab.flows = newMatrix
    g.flowTab.Unlock()
}

func (g *GPCapture) GetPcapHandleStats(timestamp int64) string {

    pkts     := atomic.LoadUint64(&g.pktsRead)
    stats, _ := g.pcapHandle.Stats()

    // CSV format the pcapHandle statistics
    statsString := strconv.FormatInt(timestamp, 10)                   +","+
        g.iface                                                       +","+
        strconv.Itoa(stats.PacketsReceived-g.stats.PacketsReceived)   +","+
        strconv.Itoa(stats.PacketsDropped-g.stats.PacketsDropped)     +","+
        strconv.Itoa(stats.PacketsIfDropped-g.stats.PacketsIfDropped) +","+
        strconv.FormatUint(pkts, 10)                                  +"\n"

    g.stats    = stats
    atomic.StoreUint64(&g.pktsRead, 0)

    return statsString
}

// Function handling thread termination from external functions ----------------------
func (g *GPCapture) InitiateTermination(ackChan chan string) {

    // send quit to capture routine
    g.quitting = true
    g.quitCaptureChan <-true
    <-g.ackQuitChan

    ackChan<-g.iface
}
