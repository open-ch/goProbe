/////////////////////////////////////////////////////////////////////////////////
//
// GPClassify.go
//
// Wrapper file for the classifier function used to determine the direction of a
// packet with respect to its Endpoints
//
// Written by Lennart Elsen
//        and Fabian  Kohn, June 2014
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

const (
	Unknown          uint8 = 0
	DirectionRemains uint8 = 1
	DirectionReverts uint8 = 2
)

// This function is responsible for running a variety of heuristics on the packet
// in order to determine its direction. This classification is important since the
// termination of flows in regular intervals otherwise results in the incapability
// to correctly assign the appropriate endpoints. Current heuristics include:
//   - investigating the TCP flags (if available)
//   - incorporating the port information (with respect to privileged ports)
//   - dissecting ICMP traffic
//
// Return value: according to above enumeration
//    0: if no classification possible
//    1: if packet direction is "request"
//    2: if packet direction is "response"
func ClassifyPacketDirection(packet *GPPacket) uint8 {

	//    TCPflags := packet.TCPflags
	sport := uint16(packet.endpoint.sport[0])<<8 | uint16(packet.endpoint.sport[1])
	dport := uint16(packet.endpoint.dport[0])<<8 | uint16(packet.endpoint.dport[1])

	// first, check the TCP flags availability
	/*    if TCPflags != 0x00 {
	          // process the TCP handshake flags to decide the direction.
	          switch TCPflags {
	          case 0x02: // SYN
	              return DirectionRemains
	          case 0x12: // SYN-ACK
	              return DirectionReverts
	          case 0x01: // FIN
	              return DirectionRemains
	          case 0x11: // FIN-ACK
	              return DirectionReverts
	          }
	      }
	*/

    // handle TCP and UDP
	if packet.endpoint.protocol == 6 || packet.endpoint.protocol == 17 {
		// non-TCP-handshake packet encountered, but port information available

		// according to RFC 6056, look for ephemeral ports in the range of 49152
		// through 65535
		if (dport < 1024 || dport == 8080 || dport == 5353 || dport == 17500 || dport == 8612 || dport == 5222) && sport > 20000 {
			return DirectionRemains
		}

		if (sport < 1024 || sport == 8080 || sport == 5353 || sport == 17500 || sport == 8612 || sport == 5222) && dport > 20000 {
			return DirectionReverts
		}
	}

    // handle multicast addresses
    if (packet.endpoint.dip[0] == 224 && packet.endpoint.dip[1] == 0) && (packet.endpoint.dip[2] == 0 || packet.endpoint.dip[2] == 1) {
        return DirectionRemains
    }

    // handle broadcast address
    if (packet.endpoint.dip[0] == 255 && packet.endpoint.dip[1] == 255 && packet.endpoint.dip[2] == 255 && packet.endpoint.dip[3] == 255) {
        return DirectionRemains
    }

	/* disregarded until further notice
	   if packet.ICMPtypeCode != 0xffff {
	   	// try ICMP codes if protocol field matches. Echo request and reply can shed
	   	// light on the situation. Other codes may help too
	   	switch packet.ICMPtypeCode {
	   	case 0x0000: // echo reply
	   		return DirectionRemains
	   	case 0x0800: // echo request
	   		return DirectionReverts
	   	}

	   }
	*/

	// if there is yet no verdict, return "Unknown"
	return Unknown
}
