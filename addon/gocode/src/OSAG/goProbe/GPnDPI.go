/////////////////////////////////////////////////////////////////////////////////
//
// GPnDPI.go
//
// Small wrapper to make available a dpi instance which can be globally used by
// all methods within the goProbe packet
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
