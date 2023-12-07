// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// arpscan implements ARP scanning of all interfaces' local networks using
// gopacket and its subpackages.  This example shows, among other things:
//   - Generating and sending packet data
//   - Reading in packet data and interpreting it
//   - Use of the 'pcap' subpackage for reading/writing
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("expected an IP address. Eg:\n$ goarp 192.168.1.1")
		os.Exit(1)
	}

	ip := os.Args[1]

	if err := run("Ethernet", "Realtek PCIe GbE Family Controller", ip); err != nil {
		panic(err)
	}
}
