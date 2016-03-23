////////////////////////////////////////////////////////////////////////////////
//
// dpi.go
//
// Written by Lennart Elsen lel@open.ch, July 2014
// Copyright (c) 2014 Open Systems AG, Switzerland
// All Rights Reserved.
//
/////////////////////////////////////////////////////////////////////////////////

// Go interface to the C-Wrapper interfacing the libprotoident C++ API
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
    GetLayer7Proto(payloadIn [4]byte, payloadOut [4]byte, observedIn uint32, observedOut uint32, serverPort uint16, clientPort uint16, transportProto uint8, payloadLenIn uint32, payloadLenOut uint32, sip [16]byte, dip [16]byte) uint16

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
func (d *DPI) GetLayer7Proto(payloadIn [4]byte, payloadOut [4]byte, observedIn uint32, observedOut uint32, serverPort uint16, clientPort uint16, transportProto uint8, payloadLenIn uint32, payloadLenOut uint32, dip [16]byte, sip [16]byte) uint16 {
    var result uint16

    // convert payload to uint32
    plIn := C.uint32_t(uint32(payloadIn[3])<<24 | uint32(payloadIn[2])<<16 | uint32(payloadIn[1])<<8 | uint32(payloadIn[0]))
    plOut := C.uint32_t(uint32(payloadOut[3])<<24 | uint32(payloadOut[2])<<16 | uint32(payloadOut[1])<<8 | uint32(payloadOut[0]))

    // convert ips to uint32
    ipOut := C.uint32_t(uint32(sip[3])<<24 | uint32(sip[2])<<16 | uint32(sip[1])<<8 | uint32(sip[0]))
    ipIn := C.uint32_t(uint32(dip[3])<<24 | uint32(dip[2])<<16 | uint32(dip[1])<<8 | uint32(dip[0]))

    // call the identifier routine from the C-Wrapper
    result = uint16(C.ProtoId_getLayer7Proto(d.idPointer, plIn, plOut,
        C.uint32_t(observedIn), C.uint32_t(observedOut),
        C.uint16_t(serverPort), C.uint16_t(clientPort),
        C.uint8_t(transportProto),
        C.uint32_t(payloadLenIn), C.uint32_t(payloadLenOut),
        ipIn, ipOut))

    return result
}
