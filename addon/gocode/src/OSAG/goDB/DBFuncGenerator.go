///////////////////////////////////////////////////////////////////////////////// 
// 
// DBFuncGenerator.go 
// 
// Wrapper file for function generators 
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

/// CONDITION FUNCTION GENERATORS ///
// closure to create a comparator function based on the condition
func condCompGenerator(attributeToCompare string) func(cond []byte, col_val []byte) bool {
    var len_bytes int

    // generate the function based on which attribute was provided. For a small
    // amount of bytes, the check is performed directly in order to avoid the
    // overhead induced by a for loop
    switch attributeToCompare {
    case "dip":
        len_bytes = 16
    case "sip":
        len_bytes = 16
    case "dport":
        return func(cond []byte, col_val []byte) bool {
            return ((cond[0] == col_val[0]) && (cond[1] == col_val[1]))
        }
    case "l7proto":
        return func(cond []byte, col_val []byte) bool {
            return ((cond[0] == col_val[0]) && (cond[1] == col_val[1]))
        }
    case "proto":
        return func(cond []byte, col_val []byte) bool {
            return cond[0] == col_val[0]
        }
    }

    // for loop which lazily checks if the bytes match
    return func(cond []byte, col_val []byte) bool {
        for i:=0; i<len_bytes; i++{
            if cond[i] != col_val[i] {
                return false
            }
        }
        return true
    }
}

// function to generate the reader functions to extract the bytes needed to
// compare values when conditions are used during runtime, without having to worry
// about offsets. Ultimately, this saves runtime as the function already 
// knows at which positions block bytes have to be extracted
func condReaderGenerator(attributeToCompare string) func(cond_bytes []byte, pos int) ([]byte, int) {
    var len_bytes int

    // generate the function based on which attribute was provided
    switch attributeToCompare {
    case "dip":
        len_bytes = 16
    case "sip":
        len_bytes = 16
    case "dport":
        len_bytes = 2
    case "l7proto":
        len_bytes = 2
    case "proto":
        len_bytes = 1
    }

    // ip assignment
    return func(cond_bytes []byte, pos int) ([]byte, int) {
        return cond_bytes[pos:pos+len_bytes], pos+len_bytes
    }
}

/// ATTRIBUTE FUNCTION GENERATORS ///
// generator for a function that reads the correct bytes into the key and returns
// the incremented position variable
func bytesToMapKeyGenerator(attribute string) func(rowBytes []byte, pos int, key *Key) int {
    switch attribute {
    case "sip":
        return func(rowBytes []byte, pos int, key *Key) int {
            for i:=0; i<16; i++{
                key.Sip[i] = rowBytes[pos+i]
            }
            return pos+16
        }
    case "dip":
        return func(rowBytes []byte, pos int, key *Key) int {
            for i:=0; i<16; i++{
                key.Dip[i] = rowBytes[pos+i]
            }
            return pos+16
        }
    case "dport":
        return func(rowBytes []byte, pos int, key *Key) int {
            key.Dport[0], key.Dport[1] = rowBytes[pos], rowBytes[pos+1]
            return pos+2
        }
    case "l7proto":
        return func(rowBytes []byte, pos int, key *Key) int {
            key.L7proto[0], key.L7proto[1] = rowBytes[pos], rowBytes[pos+1]
            return pos+2
        }
    case "proto":
        return func(rowBytes []byte, pos int, key *Key) int {
            key.Protocol = rowBytes[pos]
            return pos+1
        }
    }

    return nil
}
