/////////////////////////////////////////////////////////////////////////////////
//
// GPPacket.go
//
// Main packet Interface that provides the datastructure that is passed around
// every channel within the program. Contains the necessary information that a flow
// needs
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
	"hash"
	"hash/crc32"
)

var h hash.Hash32 = crc32.NewIEEE()

// typedef that allows us to replace the type of hash
type EPHash uint32

type GPPacket struct {
	// core fields
	endpoint      *GPEndpoint
	l7proto       uint16
	l7payload     []byte
	l7payloadSize uint16
	numBytes      uint16

	// direction indicator fields
	TCPflags byte

	// packet descriptors
	epHash        EPHash
	epHashReverse EPHash
	dirInbound    bool // packet inbound or outbound on interface
}

func computeEPHash(rawBytes []byte) EPHash {
	// reset the previous hash
	h.Reset()

	// write the current information
	h.Write(rawBytes)
	return EPHash(h.Sum32())
}

func NewGPPacket(src []byte, dst []byte, sp []byte, dp []byte, payload []byte, payloadSize uint16, proto byte, numBytes uint16, tcpFlags byte, dirInbound bool) *GPPacket {

	var (
		hashBytes        []byte
		reverseHashBytes []byte
		epHash           EPHash
		epHashReverse    EPHash
	)

	// carve out the ports
	dport := uint16(dp[0])<<8 | uint16(dp[1])
	sport := uint16(sp[0])<<8 | uint16(sp[1])

	// prepare byte arrays:
	// include different fields into the hashing arrays in order to
	// discern between session based traffic and udp traffic. When
	// session based traffic is observed, the source port is taken
	// into account. A major exception is traffic over port 53 as
	// considering every single DNS request/response would
	// significantly fill up the flow map
	if proto == 6 && dport != 53 && sport != 53 {
		hashBytes = []byte{src[0], src[1], src[2], src[3], src[4], src[5], src[6], src[7],
			src[8], src[9], src[10], src[11], src[11], src[12], src[13], src[14], src[15],
			dst[0], dst[1], dst[2], dst[3], dst[4], dst[5], dst[6], dst[7],
			dst[8], dst[9], dst[10], dst[11], dst[11], dst[12], dst[13], dst[14], dst[15],
			dp[0], dp[1],
			sp[0], sp[1],
			proto}

		reverseHashBytes = []byte{dst[0], dst[1], dst[2], dst[3], dst[4], dst[5], dst[6], dst[7],
			dst[8], dst[9], dst[10], dst[11], dst[11], dst[12], dst[13], dst[14], dst[15],
			src[0], src[1], src[2], src[3], src[4], src[5], src[6], src[7],
			src[8], src[9], src[10], src[11], src[11], src[12], src[13], src[14], src[15],
			sp[0], sp[1],
			dp[0], dp[1],
			proto}
	} else {
		hashBytes = []byte{src[0], src[1], src[2], src[3], src[4], src[5], src[6], src[7],
			src[8], src[9], src[10], src[11], src[11], src[12], src[13], src[14], src[15],
			dst[0], dst[1], dst[2], dst[3], dst[4], dst[5], dst[6], dst[7],
			dst[8], dst[9], dst[10], dst[11], dst[11], dst[12], dst[13], dst[14], dst[15],
			dp[0], dp[1],
			proto}

		reverseHashBytes = []byte{dst[0], dst[1], dst[2], dst[3], dst[4], dst[5], dst[6], dst[7],
			dst[8], dst[9], dst[10], dst[11], dst[11], dst[12], dst[13], dst[14], dst[15],
			src[0], src[1], src[2], src[3], src[4], src[5], src[6], src[7],
			src[8], src[9], src[10], src[11], src[11], src[12], src[13], src[14], src[15],
			sp[0], sp[1],
			proto}
	}

	// compute hashes
	epHash = computeEPHash(hashBytes)
	epHashReverse = computeEPHash(reverseHashBytes)

	return &GPPacket{NewGPEndpoint(src, dst, sp, dp, proto), LPI_PROTO_UNKNOWN, payload, payloadSize, numBytes, tcpFlags, epHash, epHashReverse, dirInbound}
}
