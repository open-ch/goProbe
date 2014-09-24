/////////////////////////////////////////////////////////////////////////////////
//
// GPLog.go
//
// Logging Interface that all other interfaces get access to in order to write 
// error messages to the underlying system logging facilities
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
	"log/syslog"
)

type GPLogger interface{
    Err() error
    Debug() error
    Alert() error
    Crit() error
    Emerg() error
    Info() error
    Notice() error
    Warning() error
}

type GPLog struct{
    Log *syslog.Writer
}

var SysLog *GPLog = &GPLog{nil}

func InitGPLog() error {
    var err error
    var Log *syslog.Writer
	if Log, err = syslog.New(syslog.LOG_NOTICE, "goDB"); err != nil {
        return err;
    }
    SysLog.Log = Log

    return nil;
}

// deferral function
func LogDefer() {
    recover()
}

// syslog wrapper functions
func(l *GPLog) Err(msg string) error {
    if l.Log != nil {
        return l.Log.Err(msg)
    }
    defer LogDefer()
    return nil;
}
func(l *GPLog) Debug(msg string) error {
    if l.Log != nil {
        return l.Log.Debug(msg)
    }
    defer LogDefer()
    return nil;
}

func(l *GPLog) Alert(msg string) error {
    if l.Log != nil {
        return l.Log.Alert(msg)
    }
    defer LogDefer()
    return nil;
}
func(l *GPLog) Crit(msg string) error {
    if l.Log != nil {
        return l.Log.Crit(msg)
    }
    defer LogDefer()
    return nil;
}
func(l *GPLog) Emerg(msg string) error {
    if l.Log != nil {
        return l.Log.Emerg(msg)
    }
    defer LogDefer()
    return nil;
}
func(l *GPLog) Info(msg string) error {
    if l.Log != nil {
        return l.Log.Info(msg)
    }
    defer LogDefer()
    return nil;
}
func(l *GPLog) Notice(msg string) error {
    if l.Log != nil {
        return l.Log.Notice(msg)
    }
    defer LogDefer()
    return nil;
}
func(l *GPLog) Warning(msg string) error {
    if l.Log != nil {
        return l.Log.Warning(msg)
    }
    defer LogDefer()
    return nil;
}
