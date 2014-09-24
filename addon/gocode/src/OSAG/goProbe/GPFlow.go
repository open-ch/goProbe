/////////////////////////////////////////////////////////////////////////////////
//
// GPFlow.go
//
// Main flow structure which is put into the GPMatrix and which is updated according to packet information
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

type GPFlower interface {
	UpdateFlow()
	IsWorthKeeping() bool
	HasBeenIdle()    bool
	Reset()
}

type GPFlow struct {
	endpoint        GPEndpoint
	l7proto         uint16
	nBytesRcvd      uint64
	nBytesSent      uint64
	nPktsRcvd       uint64
	nPktsSent       uint64
	pktDirectionSet bool

	// store the layer 7 payload coming from a return packet
	pktPayloadOtherDirection    []byte
	pktPayloadLenOtherDirection uint32
}

func updateDirection(packet *GPPacket) bool {
	directionSet := false
	if direction := ClassifyPacketDirection(packet); direction != Unknown {
		directionSet = true

		// switch fields if direction was opposite to the default direction
		// "DirectionRemains"
		if direction == DirectionReverts {
			packet.endpoint.sip, packet.endpoint.dip     = packet.endpoint.dip, packet.endpoint.sip
			packet.endpoint.sport, packet.endpoint.dport = packet.endpoint.dport, packet.endpoint.sport
		}
	}

	return directionSet
}

// Constructor method
func NewGPFlow(packet *GPPacket) *GPFlow {
	var (
		bytes_sent, bytes_rcvd, pkts_sent, pkts_rcvd uint64
		layer7proto                                  uint16
		payloadOtherDir                              []byte
		payloadLenOtherDir                           uint32
	)

	// set packet and byte counters with respect to its interface direction
	if packet.dirInbound {
		bytes_rcvd = uint64(packet.numBytes)
		pkts_rcvd  = 1
	} else {
		bytes_sent = uint64(packet.numBytes)
		pkts_sent  = 1
	}

	// assign current packet payload to the other direction
	payloadOtherDir    = packet.l7payload
	payloadLenOtherDir = uint32(packet.l7payloadSize)

	sport := uint16(packet.endpoint.sport[0])<<8 | uint16(packet.endpoint.sport[1])
	dport := uint16(packet.endpoint.dport[0])<<8 | uint16(packet.endpoint.dport[1])

	// try to get the packet direction
	directionSet := updateDirection(packet)

	// try to get the layer 7 protocol
	layer7proto = dpiPtr.GetLayer7Proto(packet.l7payload,
		[]byte{0x00, 0x00, 0x00, 0x00},
		uint32(packet.l7payloadSize),
		uint32(0),
		dport,
		sport,
		packet.endpoint.protocol,
		uint32(packet.l7payloadSize),
		uint32(0),
		packet.endpoint.dip,
		packet.endpoint.sip)

	return &GPFlow{(*packet.endpoint), layer7proto, bytes_rcvd, bytes_sent, pkts_rcvd, pkts_sent, directionSet, payloadOtherDir, payloadLenOtherDir}
}

// here, the values are incremented if the packet belongs to an existing flow
func (f *GPFlow) UpdateFlow(packet *GPPacket) {

	// increment packet and byte counters with respect to its interface direction
	if packet.dirInbound {
		f.nBytesRcvd += uint64(packet.numBytes)
		f.nPktsRcvd++
	} else {
		f.nBytesSent += uint64(packet.numBytes)
		f.nPktsSent++
	}

	sport := uint16(packet.endpoint.sport[0])<<8 | uint16(packet.endpoint.sport[1])
	dport := uint16(packet.endpoint.dport[0])<<8 | uint16(packet.endpoint.dport[1])

	// update layer 7 protocol in case it was not detected with the first packet
	if !(f.hasIdentifiedL7Proto()) {
		f.l7proto = dpiPtr.GetLayer7Proto(packet.l7payload,
			f.pktPayloadOtherDirection,
			uint32(packet.l7payloadSize),
			f.pktPayloadLenOtherDirection,
			dport,
			sport,
			packet.endpoint.protocol,
			uint32(packet.l7payloadSize),
			f.pktPayloadLenOtherDirection,
			packet.endpoint.dip,
			packet.endpoint.sip)
	}

	// try to update direction if necessary
	if !(f.pktDirectionSet) {
		f.pktDirectionSet = updateDirection(packet)
	}

	// assign current packet payload to the other direction
	f.pktPayloadOtherDirection    = packet.l7payload
	f.pktPayloadLenOtherDirection = uint32(packet.l7payloadSize)

}

// routine that a flow uses to check whether it has any interesting layer 7 info
// worth keeping and whether its counters are non-zero. If they are, it means that
// the flow was essentially idle in the last time interval and that it can be safely
// discarded
func (f *GPFlow) IsWorthKeeping() bool {

	// first check if the flow stores and identified layer 7 protocol
	if f.hasIdentifiedL7Proto() {

		// check if any entries have been updated lately
		if !(f.HasBeenIdle()) {
			return true
		}
	}

	return false
}

// reset all flow counters
func (f *GPFlow) Reset() {
	f.nBytesRcvd = 0
	f.nBytesSent = 0
	f.nPktsRcvd  = 0
	f.nPktsSent  = 0
}

func (f *GPFlow) hasIdentifiedL7Proto() bool {
	return f.l7proto > 3
}

func (f *GPFlow) HasBeenIdle() bool {
	return (f.nPktsRcvd == 0) && (f.nPktsSent == 0)
}
