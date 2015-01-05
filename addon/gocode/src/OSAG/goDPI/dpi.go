////////////////////////////////////////////////////////////////////////////////
//
// dpi.go
//
// Go interface to the C-Wrapper interfacing the libprotoident C++ API
//
// Written by Lennart Elsen and Fabian Kohn, July 2014
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
package dpi

/*
#cgo linux CFLAGS: -I../../../../dpi
#cgo linux LDFLAGS: -L../../../../dpi -lProtoId

#include <stdlib.h>
#include <stdio.h>

#include "ProtoId.h"

*/
import "C"

import (
	"errors"
	"unsafe"
)

type DPIer interface {
	GetLayer7Proto(payloadIn []byte, payloadOut []byte, observedIn uint32, observedOut uint32, serverPort uint16, clientPort uint16, transportProto uint8, payloadLenIn uint32, payloadLenOut uint32, sip []byte, dip []byte) uint16

	// constructors and destructors
	NewDPI() (*DPI, error)
	FreeLPI()
}

type DPI struct {
	idPointer unsafe.Pointer
}

func NewDPI() (*DPI, error) {
	// initialize protoId pointer
	p := unsafe.Pointer((*C.CProtoId)(C.ProtoId_new()))

	// initialize the protocol and libprotoident library
	var retVal int = int(C.ProtoId_initLPI(p))
	if retVal < 0 {
		return nil, errors.New("libprotoident initialization failed")
	}

	// create struct
	return &DPI{p}, nil
}

// helper routine to call the destructor and free the memory
// claimed by the unsafe pointer
func (d *DPI) FreeLPI() {
	// free the lpi library
	C.ProtoId_freeLPI(d.idPointer) 
}

// primary routine to extract the layer 7 protocol given the
// provided packet fields
func (d *DPI) GetLayer7Proto(payloadIn []byte, payloadOut []byte, observedIn uint32, observedOut uint32, serverPort uint16, clientPort uint16, transportProto uint8, payloadLenIn uint32, payloadLenOut uint32, dip []byte, sip []byte) uint16 {
	var result uint16

	// convert payload to uint32
	plIn  := C.uint32_t(uint32(payloadIn[3])<<24  | uint32(payloadIn[2])<<16  | uint32(payloadIn[1])<<8  | uint32(payloadIn[0]))
	plOut := C.uint32_t(uint32(payloadOut[3])<<24 | uint32(payloadOut[2])<<16 | uint32(payloadOut[1])<<8 | uint32(payloadOut[0]))

	// convert ips to uint32
	ipOut := C.uint32_t(uint32(sip[3])<<24 | uint32(sip[2])<<16 | uint32(sip[1])<<8 | uint32(sip[0]))
	ipIn  := C.uint32_t(uint32(dip[3])<<24 | uint32(dip[2])<<16 | uint32(dip[1])<<8 | uint32(dip[0]))

	// call the identifier routine from the C-Wrapper
	result = uint16(C.ProtoId_getLayer7Proto(d.idPointer, plIn, plOut,
		C.uint32_t(observedIn), C.uint32_t(observedOut),
		C.uint16_t(serverPort), C.uint16_t(clientPort),
		C.uint8_t(transportProto),
		C.uint32_t(payloadLenIn), C.uint32_t(payloadLenOut),
		ipIn, ipOut))

	return result
}
