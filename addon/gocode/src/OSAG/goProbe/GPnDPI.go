/////////////////////////////////////////////////////////////////////////////////
//
// GPnDPI.go
//
// Small wrapper to make available a dpi instance which can be globally used by
// all methods within the goProbe packet
//
// Written by Lennart Elsen lel@open.ch, May 2014
// Copyright (c) 2014 Open Systems AG, Switzerland
// All Rights Reserved.
//
/////////////////////////////////////////////////////////////////////////////////

package goProbe

import (
    "OSAG/goDPI"
)

var dpiPtr *dpi.DPI

// iterator variable that needs to be adapted whenever new protocols are added
// to libprotoident
const LPI_PROTO_LAST uint16 = 294

// dpi vars
var (
    LPI_PROTO_INVALID     uint16 = 0
    LPI_PROTO_NO_PAYLOAD  uint16 = 1
    LPI_PROTO_UNSUPPORTED uint16 = 2
    LPI_PROTO_UNKNOWN     uint16 = 3
)

func InitDPI() error {
    var (
        err error = nil
    )

    dpiPtr, err = dpi.NewDPI()

    return err
}

func DeleteDPI() {
    dpiPtr.FreeLPI()
}
