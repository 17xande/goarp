package main

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func findInterface(name string) (*net.Interface, error) {
	// Get a list of all interfaces.
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	for _, iface := range ifaces {
		// fmt.Printf("%+v\n", iface)
		if iface.Name == name {
			return &iface, nil
		}
	}

	return nil, fmt.Errorf("could not find interface with name: %s", name)
}

func findPcapInterface(description string) (*pcap.Interface, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("can't find pcap devices: %w", err)
	}

	for _, dev := range devices {
		if dev.Description == description {
			return &dev, nil
		}
	}

	return nil, fmt.Errorf("could not find device with description: %s", description)
}

func findIPv4(iface *pcap.Interface) (net.IP, error) {
	for _, iaddr := range iface.Addresses {
		if ip4 := iaddr.IP.To4(); ip4 != nil {
			return ip4, nil
		}
	}

	// TODO: filter out localhost and bad addresses.

	return nil, fmt.Errorf("could not get an IPv4 address from this interface")
}

func readARP(handle *pcap.Handle, iface *net.Interface, targetIP netip.Addr, stop chan struct{}, result chan string) {
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	in := src.Packets()

	fmt.Println("listening for packets")
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			fmt.Println("stopping")
			return
		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				// Not an ARP packet.
				continue
			}
			arp := arpLayer.(*layers.ARP)

			res := fmt.Sprintf("IP %v is assigned to device with MAC %v", net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress))

			// If the packet's source MAC is equal this this mechine's MAC, this is a packet I sent.
			if bytes.Equal([]byte(iface.HardwareAddr), arp.SourceHwAddress) {
				// This is a packet I sent.
				continue
			}
			// If the packet's destination address is not this machine's MAC, this packet is not for us. Why am I getting it.
			if !bytes.Equal([]byte(iface.HardwareAddr), arp.DstHwAddress) {
				// fmt.Printf("This is not meant for us: Source Mac: %v Dest Mac %v\n", net.IP(arp.SourceProtAddress), net.IP(arp.DstProtAddress))
				continue
			}
			// Note:  we might get some packets here that aren't responses to ones we've sent,
			// if for example someone else sends US an ARP request.  Doesn't much matter, though...
			// all information is good information :)
			packetSourceAddress := netip.AddrFrom4([4]byte(arp.SourceProtAddress))
			if targetIP.Compare(packetSourceAddress) != 0 {

				fmt.Println("this is not the address I'm looking for:", res)
				continue
			}

			result <- res
		}
	}
}

// writeARP writes an ARP request for each address on our local network to the
// pcap handle.
func writeARP(handle *pcap.Handle, iface *net.Interface, sourceAddr, targetAddr netip.Addr) error {
	// Set up all the layers' fields we can.
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: sourceAddr.AsSlice(),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    targetAddr.AsSlice(),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	gopacket.SerializeLayers(buf, opts, &eth, &arp)
	fmt.Printf("Packet written:\n%+v\n", arp)
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return err
	}

	return nil
}

func run(ifaceName, pCapIfaceName, targetIP string) error {
	ifac, err := findInterface(ifaceName)
	if err != nil {
		return fmt.Errorf("can't find interface: %w", err)
	}

	iface, err := findPcapInterface(pCapIfaceName)
	if err != nil {
		return fmt.Errorf("can't find pcap interface: %w", err)
	}

	ip4, err := findIPv4(iface)
	if err != nil {
		return fmt.Errorf("can't find IPv4 address: %w", err)
	}

	// fmt.Printf("ip4: %s\n", ip4)

	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("can't pcap.OpenLive: %w", err)
	}

	// Start a goroutine to read in packet data.
	stop := make(chan struct{})
	result := make(chan string)
	tIP, err := netip.ParseAddr(targetIP)
	if err != nil {
		panic(err)
	}
	fmt.Printf("target ip: %+v\n", tIP)
	go readARP(handle, ifac, tIP, stop, result)
	defer close(stop)

	destination := netip.MustParseAddr(targetIP)
	intIP4 := netip.AddrFrom4([4]byte(ip4))

	time.Sleep(200 * time.Millisecond)

	if err := writeARP(handle, ifac, intIP4, destination); err != nil {
		return fmt.Errorf("can't writeARP: %w", err)
	}

	r := <-result

	fmt.Println(r)

	return nil
}
