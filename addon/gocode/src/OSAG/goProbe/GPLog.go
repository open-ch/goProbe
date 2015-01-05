/////////////////////////////////////////////////////////////////////////////////
//
// GPLog.go
//
// Logging Interface that all other interfaces get access to in order to write 
// error messages to the underlying system logging facilities
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
	"log/syslog"
)

var SysLog *syslog.Writer

const SLOG_ADDR = "127.0.0.1"
const SLOG_PORT = "514"

func InitGPLog() error {

    var err error
	if SysLog, err = syslog.Dial("udp", SLOG_ADDR+":"+SLOG_PORT, syslog.LOG_NOTICE, "goProbe"); err != nil {
        return err;
    }
    return nil;
}

