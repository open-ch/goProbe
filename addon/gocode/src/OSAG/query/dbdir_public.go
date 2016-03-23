/////////////////////////////////////////////////////////////////////////////////
//
// dbdir_public.go
//
// Written by Lennart Elsen lel@open.ch, February 2016
// Copyright (c) 2016 Open Systems AG, Switzerland
// All Rights Reserved.
//
/////////////////////////////////////////////////////////////////////////////////

// +build !OSAG

package main

import (
    "encoding/json"
    "fmt"
    "io/ioutil"
    "os"
)

// set this variable on compile time
var goprobeConfigPath string

type gpConfig struct {
    DBPath     string                 `json:"db_path"`
    Interfaces map[string]interface{} `json:"interfaces"`
}

func getDefaultDBDir() (string, error) {
    var config gpConfig

    fd, err := os.Open(goprobeConfigPath)
    if err != nil {
        return "", err
    }
    defer fd.Close()

    data, err := ioutil.ReadAll(fd)
    if err != nil {
        return "", err
    }

    if err := json.Unmarshal(data, &config); err != nil {
        return "", err
    }

    if config.DBPath == "" {
        return "", fmt.Errorf("Database path must not be empty")
    }

    return config.DBPath, nil
}
