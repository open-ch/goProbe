goProbe
===========

This package comprises:

* goProbe - A lightweight, concurrent, network packet aggregator
* goDB - A small, columnar database
* goQuery - A query front-end used to read out data acquired by goProbe and stored by goDB

As the name suggests, all components are written in Google [go](https://golang.org/).

Introduction
------------

Today, targeted analyses of network traffic patterns have become increasingly difficult due to the sheer amount of traffic encountered. To enable them, traffic needs to be captured and examined and broken down to key descriptors which yield a condensed explanation of the underlying data.

The [NetFlow](http://www.ietf.org/rfc/rfc3954.txt) standard was introduced to address this reduction. It uses the concept of flows, which combine packets based on a set of shared packet attributes. NetFlow information is usually captured on one device and collected in a central database on another device. Several software probes are available, implementing NetFlow exporters and collectors.

goProbe deviates from traditional NetFlow as flow capturing and collection is run on the same device and the flow fields reduced. It was designed as a lightweight, standalone system, providing both optimized packet capture and a storage backend tailored to the flow data.

goProbe
-------------------------
`goProbe` captures packets using [libpcap](http://www.tcpdump.org/) and [gopacket](https://code.google.com/p/gopacket/) and extracts several attributes which are used to classify the packet in a flow-like data structure:

* Source and Destination IP
* IP Protocol
* Destination Port (if available)
* Application Layer Protocol

Available flow counters are:

* Bytes sent and received
* Packet sent and received
   
In summary: *a goProbe-flow is not a NetFlow-flow*.

The flow data is written out to a custom colum store called `goDB`, which was specifically designed to accomodate goProbe's data. Each of the above attributes is stored in a column file

### Usage

Capturing is performed concurrently by goProbe on multiple interfaces which are specified as arguments to the program, which is started as follows (as `root`):

```
/usr/local/goProbe/bin/goProbe <iface 1> <iface 2> ... <iface n>
```
The capturing probe can be run as a daemon via

```
/etc/init.d/goprobe.init {start|stop|status|restart|force-reload}
```

goDB
--------------------------
The flow records are stored block-wise on a five minute basis in their respective attribute files. The database is partitioned on a per day basis, which means that for each day, a new folder is created which holds the attribute files for all flow records written throughout the day.

Blocks are compressed using [lz4](https://code.google.com/p/lz4/) compression, which was chosen to enable both swift decompression and good data compression ratios.

`goDB` is a package which can be imported by other `go` applications.

goQuery
--------------------------

`goQuery` is the query front which is used to access and aggregate the flow information stored in the database. The following query types are supported:

* Top talkers: show data traffic volume of all unique IP pairs
* Top Applications (port/protocol): traffic volume of all unique destination port-transport protocol pairs, e.g., 443/TCP
* Top Applications (layer 7): traffic volume by application layer protocol, e.g. SSH, HTTP, etc.

### Usage

For more information, type `/usr/local/goProbe/bin/goQuery -h`

Example Output
------

```
root@analyzer# /usr/local/goProbe/bin/goQuery -i eth0 -n 10 -c proto=TCP talk_conv
Your query: talk_conv
Conditions: proto=TCP
Sort by:    accumulated data volume (sent and received)
Interface:  eth0
Query produced 779 hits and took 33.66236ms 

                                  sip                   dip    packets       %   data vol.       %
                       215.142.239.52        215.142.238.87    46.13 M   58.33    28.92 GB   89.17
                       215.142.239.52       215.142.226.100    17.74 M   22.43     1.46 GB    4.50
                       215.142.239.52       215.142.238.100    14.08 M   17.80     1.16 GB    3.57
                       215.142.239.52       215.142.226.131   320.68 k    0.41   182.69 MB    0.55
     fd03:ca0:7:c08:a0ae:118:867:d7e3   fd03:ca0:8:c0c::165    98.98 k    0.13   173.35 MB    0.52
                       215.142.239.52       215.142.238.167   266.83 k    0.34   139.72 MB    0.42
                       215.142.239.52        215.142.228.16    23.89 k    0.03   124.34 MB    0.37
    fd03:ca0:7:c08:d910:9c63:f26f:3d2   fd03:ca0:8:c0c::165    80.99 k    0.10   119.30 MB    0.36
   fd03:ca0:7:c08:28d4:b3ee:c16c:9ba4   fd03:ca0:8:c0c::165    49.06 k    0.06    72.62 MB    0.22
   fd03:ca0:7:c08:4c6e:86bb:aec1:1072   fd03:ca0:8:c0c::165    15.91 k    0.02    23.83 MB    0.07

Overall packets: 79.07 M , Overall data volume: 32.44 GB
```

Installation
------------

This package was designed to work out of the box. Thus, you do not even need the `go` environment. All of the dependencies are downloaded during package configuration. To install the package, go to the directory into which you cloned this repository and run the following commands (as `root`):

```
make all
```

Above command runs the following targets:

* `make clean`: removes all dependencies and compiled binaries
* `make configure`: downloads the dependencies, configures them and applies patches (if necessary)
* `make compile`: compiles dependencies, goProbe and goQuery 
* `make install`: set up package as a binary tree. The binaries and used libraries are placed in `/usr/local/goProbe` per default. The init script can be found under `/etc/init.d/goprobe.init`. It is also possible to install a cronjob used to clean up outdated database entries. It is not installed by default. Uncomment the line in the Makefile if you need this feature. The cronjob can be found in `/etc/cron.d/goprobe.cron`

Authors & Contributors
----------------------

Lennart Elsen and Fabian Kohn, Open Systems AG

This software was developed at [Open Systems AG](https://www.open.ch/) in close collaboration with the [Distributed Computing Group](http://www.disco.ethz.ch/) at the [Swiss Federal Institute of Technology](https://www.ethz.ch/en.html).

License
-------
See the LICENSE file for usage conditions.
