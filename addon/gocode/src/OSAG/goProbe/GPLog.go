/////////////////////////////////////////////////////////////////////////////////
//
// GPLog.go
//
// Logging Interface that all other interfaces get access to in order to write
// error messages to the underlying system logging facilities
//
// Written by Lennart Elsen lel@open.ch, May 2014
// Copyright (c) 2014 Open Systems AG, Switzerland
// All Rights Reserved.
//
/////////////////////////////////////////////////////////////////////////////////

package goProbe

import (
    "log/syslog"
)

var SysLog *syslog.Writer

const (
    SLOG_ADDR = "127.0.0.1"
    SLOG_PORT = "514"
)

func InitGPLog() error {

    var err error
    if SysLog, err = syslog.Dial("udp", SLOG_ADDR+":"+SLOG_PORT, syslog.LOG_NOTICE, "goProbe"); err != nil {
        return err
    }
    return nil
}
