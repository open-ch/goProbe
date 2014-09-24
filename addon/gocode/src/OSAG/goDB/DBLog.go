/////////////////////////////////////////////////////////////////////////////////
//
// DBLog.go
//
// Log.ing Interface that all other interfaces get access to in order to write 
// error messages to the underlying system logging facilities
//
// Written by Lennart Elsen
//        and Fabian  Kohn, July 2014
// Copyright (c) 2014 Open Systems AG, Switzerland
// All Rights Reserved.
//
/////////////////////////////////////////////////////////////////////////////////
/* This code has been developed by Open Systems AG
 *
 * goDB is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * goDB is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with goProbe; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/
package goDB

import (
	"log/syslog"
)

type DBLogger interface{
    Err() error
    Debug() error
    Alert() error
    Crit() error
    Emerg() error
    Info() error
    Notice() error
    Warning() error
}

type DBLog struct{
    Log *syslog.Writer
}

var SysLog *DBLog = &DBLog{nil}

func InitDBLog() error {
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
func(l *DBLog) Err(msg string) error {
    if l.Log != nil {
        return l.Log.Err(msg)
    }
    defer LogDefer()
    return nil;
}
func(l *DBLog) Debug(msg string) error {
    if l.Log != nil {
        return l.Log.Debug(msg)
    }
    defer LogDefer()
    return nil;
}

func(l *DBLog) Alert(msg string) error {
    if l.Log != nil {
        return l.Log.Alert(msg)
    }
    defer LogDefer()
    return nil;
}
func(l *DBLog) Crit(msg string) error {
    if l.Log != nil {
        return l.Log.Crit(msg)
    }
    defer LogDefer()
    return nil;
}
func(l *DBLog) Emerg(msg string) error {
    if l.Log != nil {
        return l.Log.Emerg(msg)
    }
    defer LogDefer()
    return nil;
}
func(l *DBLog) Info(msg string) error {
    if l.Log != nil {
        return l.Log.Info(msg)
    }
    defer LogDefer()
    return nil;
}
func(l *DBLog) Notice(msg string) error {
    if l.Log != nil {
        return l.Log.Notice(msg)
    }
    defer LogDefer()
    return nil;
}
func(l *DBLog) Warning(msg string) error {
    if l.Log != nil {
        return l.Log.Warning(msg)
    }
    defer LogDefer()
    return nil;
}
