///////////////////////////////////////////////////////////////////////////////// 
// 
// GPGeneralDefs.go 
// 
// General type definitions for querying and parsing parameters 
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
package goDB

var QueryTypes = map[string] []string {
  "talk_conv"     : []string{"sip","dip"},
  "talk_src"      : []string{"sip"},
  "talk_dst"      : []string{"dip"},
  "apps_port"     : []string{"dport","protocol"},
  "apps_dpi"      : []string{"l7proto"},
  "agg_talk_port" : []string{"sip", "dip", "dport", "proto"},
}

// struct which makes the handling of conditions more convenient
type Condition struct {
    Attribute  string
    CondValue  []byte

    ReadColVal func(condFileBytes []byte, pos int) ([]byte, int)
    Compare    func(condValue []byte, colValue []byte) bool
}

func NewCondition(attribute string, condValue []byte) Condition{
    return Condition{attribute, condValue,
        condReaderGenerator(attribute),
        condCompGenerator(attribute)}
}

// struct which generalizes a query
type Query struct {
    // list of attributes that will be compared, e.g. "dip" "sip"
    // in a "talk_conv" query
    Attributes []Attribute
    Conditions []Condition

    ResultMap  map[Key]*Val

    MapChan    chan map[Key]*Val
    QuitChan   chan bool
}

func NewQuery(queryType string, conds []Condition, mapChan chan map[Key]*Val, quitChan chan bool) *Query{
    var attr []Attribute

    switch queryType {
    case "talk_conv":
        attr = make([]Attribute, 2)
        attr = []Attribute{NewAttribute("sip"), NewAttribute("dip")}
    case "talk_src":
        attr = make([]Attribute, 1)
        attr = []Attribute{NewAttribute("sip")}
    case "talk_dst":
        attr = make([]Attribute, 1)
        attr = []Attribute{NewAttribute("dip")}
    case "apps_port":
        attr = make([]Attribute, 2)
        attr = []Attribute{NewAttribute("dport"), NewAttribute("proto")}
    case "apps_dpi":
        attr = make([]Attribute, 1)
        attr = []Attribute{NewAttribute("l7proto")}
    case "agg_talk_port":
        attr = make([]Attribute, 4)
        attr = []Attribute{NewAttribute("sip"), NewAttribute("dip"), NewAttribute("dport"), NewAttribute("proto")}
    }

    return &Query{attr, conds,
        nil,
        mapChan, quitChan}
}

type Attribute struct {
    Name              string
    CopyRowBytesToKey func(rowBytes []byte, pos int, key *Key) int
}

func NewAttribute(name string) Attribute{
    return Attribute{name, bytesToMapKeyGenerator(name)}
}

type GeneralConf struct {
    // interface list
    QueryType     string
    Iface         string
    Conditions    string
    NumResults    int
    Help          bool
    HelpAdmin     bool
    WipeAdmin     bool
    CleanAdmin    int64
    External      bool
    Sort          bool
    SortAscending bool
    Incoming      bool
    Outgoing      bool
    First         string
    Last          string
    BaseDir       string
    ListDB        bool
    Format        string
}

type Key struct {
    Sip      [16]byte
    Dip      [16]byte
    Dport     [2]byte
    Protocol     byte
    L7proto   [2]byte
}

type Val struct {
    NBytesRcvd      uint64
    NBytesSent      uint64
    NPktsRcvd       uint64
    NPktsSent       uint64
}

type DBData struct {
    // counters
    Bytes_rcvd []byte
    Bytes_sent []byte
    Pkts_rcvd  []byte
    Pkts_sent  []byte

    // attributes
    Dip        []byte
    Sip        []byte
    Dport      []byte
    L7proto    []byte
    Proto      []byte

    // metadata (important for folder naming)
    Tstamp     int64
    Iface      string
}

// constructor for the DBData struct in case it needs to be set from an external
// go program that included goProbe
func NewDBData(br []byte, bs []byte, pr []byte, ps []byte, dip []byte, sip []byte, dport []byte, l7proto []byte, proto []byte, tstamp int64, iface string) DBData{
    return DBData{br, bs, pr, ps, dip, sip, dport, l7proto, proto, tstamp, iface}
}

// generic helper functions
func PutUint16(b []byte) uint16 {
    return uint16(b[0])<<8 | uint16(b[1])
}

func PutUint32(b []byte) uint32 {
    return uint32(b[0])<<24  | uint32(b[1])<<16  |
           uint32(b[2])<<8   | uint32(b[3])
}

func PutUint64(b []byte) uint64 {
    return uint64(b[0])<<56  | uint64(b[1])<<48  |
           uint64(b[2])<<40  | uint64(b[3])<<32  |
           uint64(b[4])<<24  | uint64(b[5])<<16  |
           uint64(b[6])<<8   | uint64(b[7])
}

func PutInt64(b []byte) int64 {
    return int64(b[0])<<56  | int64(b[1])<<48  |
           int64(b[2])<<40  | int64(b[3])<<32  |
           int64(b[4])<<24  | int64(b[5])<<16  |
           int64(b[6])<<8   | int64(b[7])
}
