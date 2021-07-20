/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package tun

/* Implementation of the TUN device interface for linux
 */

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"path"
	"sync"
	"time"

	"encoding/json"

	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"git.fd.io/govpp.git"
	"git.fd.io/govpp.git/adapter/socketclient"
	"git.fd.io/govpp.git/binapi/ethernet_types"
	interfaces "git.fd.io/govpp.git/binapi/interface"
	"git.fd.io/govpp.git/binapi/interface_types"
	"git.fd.io/govpp.git/binapi/l2"
	"git.fd.io/govpp.git/binapi/memif"
	"git.fd.io/govpp.git/extras/libmemif"

	"github.com/sirupsen/logrus"
	logger "github.com/sirupsen/logrus"
)

const (
	ifReqSize = unix.IFNAMSIZ + 64

	ENV_VPP_MEMIF_SOCKET_DIR = "VPP_MEMIF_SOCKET_DIR"
	ENV_VPP_MEMIF_CONFIG_DIR = "VPP_MEMIF_CONFIG_DIR"
	ENV_VPP_SOCKET_PATH      = "VPP_API_SOCKET_PATH"
)

var (
	//read from env
	vppMemifSocketDir = "/var/run/wggo-vpp"
	vppMemifConfigDir = "/etc/wggo-vpp"
	vppApiSocketPath  = socketclient.DefaultSocketName // Path to VPP binary API socket file, default is /run/vpp/api.
	//read from json
	vppBridgeID      = uint32(4242)
	defaultGwMacAddr = "42:42:42:42:42:42"
	//internal
	NumQueues       = uint8(1)
	ARP_NS_cooldown = int64(3)
	onConnectWg     sync.WaitGroup
)

type InterfaceConfig struct {
	Uid                   uint32
	Secret                string
	GateWayMacAddr        string
	IPv4ArpResponseRanges []string
	IPv4ArpLearningRanges []string
	IPv6NdpNeighAdvRanges []string
	IPv6NdpLearningRanges []string
	VppBridgeID           uint32
}

type NativeTun struct {
	memif                *libmemif.Memif
	memifSockPath        string
	name                 string
	selfIPv4ARPRspRanges []net.IPNet
	selfIPv6NDPRspRanges []net.IPNet
	selfIPv4ARPLrnRanges []net.IPNet
	selfIPv6NDPLrnRanges []net.IPNet
	selfIPv4ARPTable     map[[4]byte]net.HardwareAddr
	selfIPv4ARPTime      map[[4]byte]int64
	selfIPv6NeiTable     map[[16]byte]net.HardwareAddr
	selfIPv6NeiTime      map[[16]byte]int64
	selfIfMacAddr        ethernet_types.MacAddress
	vppIfMacAddr         ethernet_types.MacAddress
	gwMacAddr            net.HardwareAddr
	ifid                 uint32
	SwIfIndex            interface_types.InterfaceIndex
	secret               string
	RxQueues             int
	RxintCh              <-chan uint8
	RxintErrCh           <-chan error
	TxQueues             int
	TxCount              uint
	tunFile              *os.File
	tempMTU              int

	logger                  *logrus.Logger
	errors                  chan error // async error handling
	events                  chan Event // device related events
	statusListenersShutdown chan struct{}
}

func (tun *NativeTun) File() *os.File {
	return tun.tunFile
}

func (tun *NativeTun) setMTU(n int) error {
	// connect to VPP
	conn, err := govpp.Connect(vppApiSocketPath)
	if err != nil {
		log.Fatalln("ERROR: connecting to VPP failed:", err)
	}
	defer conn.Disconnect()
	// create a channel
	ch, err := conn.NewAPIChannel()
	if err != nil {
		log.Fatalln("ERROR: creating channel failed:", err)
	}
	defer ch.Close()
	if err := ch.CheckCompatiblity(interfaces.AllMessages()...); err != nil {
		return err
	}
	interfacservice := interfaces.NewServiceClient(conn)
	// set int state memif1/1 up

	_, err = interfacservice.SwInterfaceSetMtu(context.Background(), &interfaces.SwInterfaceSetMtu{
		SwIfIndex: tun.SwIfIndex,
		Mtu:       []uint32{uint32(n)},
	})
	if err := ch.CheckCompatiblity(interfaces.AllMessages()...); err != nil {
		return err
	}
	tun.tempMTU = n
	return nil

}

func (tun *NativeTun) MTU() (int, error) {
	// connect to VPP
	return tun.tempMTU, nil
}

func (tun *NativeTun) Name() (string, error) {
	return tun.name, nil
}

func (tun *NativeTun) nameSlow() (string, error) {
	return tun.name, nil
}

func (tun *NativeTun) getTxQueueID() uint8 {
	if tun.TxQueues == 1 {
		return 0
	}
	tun.TxCount++
	return uint8(tun.TxCount % uint(tun.TxQueues))
}

func (tun *NativeTun) getNeighbor(queueID uint8, srcIPv6 [16]byte, dstIPv6 [16]byte) ([]byte, error) {
	if mac, ok := tun.selfIPv6NeiTable[dstIPv6]; ok {
		return mac, nil
	}
	for _, ipv6range := range tun.selfIPv6NDPLrnRanges {
		if ipv6range.Contains(net.IP(dstIPv6[:])) {
			if time.Now().Unix()-tun.selfIPv6NeiTime[dstIPv6] > int64(ARP_NS_cooldown) {
				tun.selfIPv6NeiTime[dstIPv6] = time.Now().Unix()
				tun.sendNDNS(queueID, srcIPv6[:], dstIPv6[:])
				tun.logger.Debugf("Send NS")
			}
			return tun.gwMacAddr, errors.New("Dst not reachable")
		}
	}
	return tun.gwMacAddr, nil
}

func (tun *NativeTun) getARP(queueID uint8, srcIPv4 [4]byte, dstIPv4 [4]byte) ([]byte, error) {
	if mac, ok := tun.selfIPv4ARPTable[dstIPv4]; ok {
		return mac, nil
	}
	for _, ipv4range := range tun.selfIPv4ARPLrnRanges {
		if ipv4range.Contains(net.IP(dstIPv4[:])) {
			if time.Now().Unix()-tun.selfIPv4ARPTime[dstIPv4] > int64(ARP_NS_cooldown) {
				tun.selfIPv4ARPTime[dstIPv4] = time.Now().Unix()
				tun.sendARPRequest(queueID, srcIPv4[:], dstIPv4[:])
				tun.logger.Debugf("Send ARP request")
			}
			return tun.gwMacAddr, errors.New("Dst not reachable")
		}
	}
	return tun.gwMacAddr, nil
}

func (tun *NativeTun) Write(buf []byte, offset int) (int, error) {
	// reserve space for header
	buf = buf[offset-14:]
	queueID := tun.getTxQueueID()
	// add packet information header
	copy(buf[6:12], tun.selfIfMacAddr[:])
	if buf[14]>>4 == ipv6.Version {
		var srcIPv6 [16]byte
		var dstIPv6 [16]byte
		copy(srcIPv6[:], buf[22:38])
		copy(dstIPv6[:], buf[38:54])
		dstmac, err := tun.getNeighbor(queueID, srcIPv6, dstIPv6)
		if err != nil {
			return 0, nil
		}
		copy(buf[0:6], dstmac)

		buf[12] = 0x86
		buf[13] = 0xdd
	} else {
		var srcIPv4 [4]byte
		var dstIPv4 [4]byte
		copy(srcIPv4[:], buf[26:30])
		copy(dstIPv4[:], buf[30:34])
		dstmac, err := tun.getARP(queueID, srcIPv4, dstIPv4)
		if err != nil {
			return 0, nil
		}
		copy(buf[0:6], dstmac)

		buf[12] = 0x08
		buf[13] = 0x00
	}

	n, err := tun.memif.TxBurst(queueID, []libmemif.RawPacketData{buf})

	return len(buf) * int(n), err
}

func (tun *NativeTun) Flush() error {
	// TODO: can flushing be implemented by buffering and using sendmmsg?
	return nil
}

func Key(ip net.IP) string {
	return string(ip.To16()) // Simple []byte => string conversion
}

// DumpPacket prints a human-readable description of the packet.
func (tun *NativeTun) DumpPacket(packetData libmemif.RawPacketData) {
	packet := gopacket.NewPacket(packetData, layers.LayerTypeEthernet, gopacket.Default)
	tun.logger.Debugf(packet.Dump())
}

func (tun *NativeTun) LearnARP(ipv4 [4]byte, macAddr net.HardwareAddr) {
	if bytes.Equal(tun.selfIPv4ARPTable[ipv4], macAddr) {
		return
	}
	for _, ipv4range := range tun.selfIPv4ARPLrnRanges {
		if ipv4range.Contains(net.IP{ipv4[0], ipv4[1], ipv4[2], ipv4[3]}) {
			tun.selfIPv4ARPTable[ipv4] = macAddr
		}
	}
}

func (tun *NativeTun) LearnNDP(ipv6 [16]byte, macAddr net.HardwareAddr) {
	if bytes.Equal(tun.selfIPv6NeiTable[ipv6], macAddr) {
		return
	}
	for _, ipv6range := range tun.selfIPv6NDPLrnRanges {
		if ipv6range.Contains(net.IP{ipv6[0], ipv6[1], ipv6[2], ipv6[3], ipv6[4], ipv6[5], ipv6[6], ipv6[7], ipv6[8], ipv6[9], ipv6[10], ipv6[11], ipv6[12], ipv6[13], ipv6[14], ipv6[15]}) {
			tun.selfIPv6NeiTable[ipv6] = macAddr
		}
	}
}

func (tun *NativeTun) Read(buf []byte, offset int) (n int, err error) {
	var hwAddr = tun.selfIfMacAddr.ToMAC()
	select {
	case err = <-tun.RxintErrCh:
		tun.logger.Errorf("libmemif.Memif.RxintErr() error: %v\n", err)
		return 0, err
	case err = <-tun.errors:
		if err == nil {
			err = errors.New("Device closed")
		}
		tun.logger.Errorf("tun error: %v\n", err)
		return 0, err
	case queueID := <-tun.RxintCh:
		packets, err := tun.memif.RxBurst(queueID, 1)
		if err != nil {
			tun.logger.Errorf("libmemif.Memif.RxBurst() error: %v\n", err)
			return 0, err
		}
		if len(packets) == 0 {
			// No more packets to read until the next interrupt.
			break
		}
		for _, packetData := range packets {
			//check if dst mac addr is a boardcast mac
			destMac := packetData[0:6]

			if bytes.Equal(destMac, net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) {
				packet := gopacket.NewPacket(packetData, layers.LayerTypeEthernet, gopacket.Default)
				ethLayer := packet.Layer(layers.LayerTypeEthernet)
				if ethLayer == nil {
					tun.logger.Debugf("received an unhandled packet: Missing ETH layer.")
					return 0, nil
				}
				eth, _ := ethLayer.(*layers.Ethernet)
				if eth.EthernetType == layers.EthernetTypeARP {
					arpLayer := packet.Layer(layers.LayerTypeARP)
					if arpLayer != nil {
						arp, _ := arpLayer.(*layers.ARP)
						var srcIPv4 [4]byte
						var dstIPv4 [4]byte
						copy(srcIPv4[:], arp.SourceProtAddress)
						copy(dstIPv4[:], arp.DstProtAddress)
						if arp.Operation == layers.ARPRequest {
							if _, ok := tun.selfIPv4ARPTable[dstIPv4]; ok {
								err := tun.sendARPReply(queueID, hwAddr, eth.SrcMAC, hwAddr, arp.DstProtAddress, eth.SrcMAC, arp.SourceProtAddress)
								return 0, err
							}
							for _, validipv4 := range tun.selfIPv4ARPRspRanges {
								if validipv4.Contains(arp.DstProtAddress) {
									tun.LearnARP(srcIPv4, eth.SrcMAC)
									err := tun.sendARPReply(queueID, hwAddr, eth.SrcMAC, hwAddr, arp.DstProtAddress, eth.SrcMAC, arp.SourceProtAddress)
									return 0, err
								}
							}
						} else if arp.Operation == layers.ARPReply {
							tun.LearnARP(dstIPv4, eth.SrcMAC)
						}
					}
				}
			}
			if bytes.Equal(destMac[0:2], []byte{0x33, 0x33}) {
				packet := gopacket.NewPacket(packetData, layers.LayerTypeEthernet, gopacket.Default)
				ethLayer := packet.Layer(layers.LayerTypeEthernet)
				if ethLayer == nil {
					tun.logger.Debugf("received an unhandled packet: Missing ETH layer.")
					return 0, nil
				}
				eth, _ := ethLayer.(*layers.Ethernet)

				if eth.EthernetType == layers.EthernetTypeIPv6 {
					ipLayer := packet.Layer(layers.LayerTypeIPv6)
					icmpLayer := packet.Layer(layers.LayerTypeICMPv6NeighborSolicitation)
					if icmpLayer != nil {
						ip, _ := ipLayer.(*layers.IPv6)
						icmp, _ := icmpLayer.(*layers.ICMPv6NeighborSolicitation)
						var srcIPv6 [16]byte
						var dstIPv6 [16]byte
						copy(srcIPv6[:], ip.SrcIP.To16())
						copy(dstIPv6[:], icmp.TargetAddress)
						if _, ok := tun.selfIPv6NeiTable[dstIPv6]; ok {
							err := tun.sendNDNA(queueID, hwAddr, eth.SrcMAC, icmp.TargetAddress, ip.SrcIP, icmp.TargetAddress, hwAddr)
							return 0, err
						}
						for _, validipv6 := range tun.selfIPv6NDPRspRanges {
							if validipv6.Contains(icmp.TargetAddress) {
								tun.LearnNDP(srcIPv6, eth.SrcMAC)
								err := tun.sendNDNA(queueID, hwAddr, eth.SrcMAC, icmp.TargetAddress, ip.SrcIP, icmp.TargetAddress, hwAddr)
								return 0, err
							}
						}
					}
				}
			}
			if bytes.Equal(destMac, tun.selfIfMacAddr.ToMAC()) {
				if len(packetData) >= 42 && bytes.Equal(packetData[12:14], []byte{0x08, 0x06}) { //arp
					packet := gopacket.NewPacket(packetData, layers.LayerTypeEthernet, gopacket.Default)
					ethLayer := packet.Layer(layers.LayerTypeEthernet)
					if ethLayer == nil {
						tun.logger.Debugf("received an unhandled packet: Missing ETH layer.")
						return 0, nil
					}
					eth, _ := ethLayer.(*layers.Ethernet)
					if eth.EthernetType == layers.EthernetTypeARP {
						arpLayer := packet.Layer(layers.LayerTypeARP)
						if arpLayer != nil {
							arp, _ := arpLayer.(*layers.ARP)
							if arp.Operation == layers.ARPReply {
								var srcIPv4 [4]byte
								copy(srcIPv4[:], arp.SourceProtAddress)
								tun.LearnARP(srcIPv4, eth.SrcMAC)
								tun.logger.Debugf("received an arp reply, arp learned")
								tun.DumpPacket(packetData)
								return 0, nil
							}
						}
					}
				} else if len(packetData) == 86 && bytes.Equal(packetData[12:14], []byte{0x86, 0xdd}) && packetData[20] == 58 && packetData[54] == 136 {
					// 86dd: ipv6 / 58: icmpv6  / 135: neighbor adv
					packet := gopacket.NewPacket(packetData, layers.LayerTypeEthernet, gopacket.Default)
					ethLayer := packet.Layer(layers.LayerTypeEthernet)
					if ethLayer == nil {
						tun.logger.Debugf("received an unhandled packet: Missing ETH layer.")
						return 0, nil
					}
					eth, _ := ethLayer.(*layers.Ethernet)

					if eth.EthernetType == layers.EthernetTypeIPv6 {
						icmpLayer := packet.Layer(layers.LayerTypeICMPv6NeighborAdvertisement)
						if icmpLayer != nil {
							icmp, _ := icmpLayer.(*layers.ICMPv6NeighborAdvertisement)
							var dstip6 [16]byte
							copy(dstip6[:], icmp.TargetAddress)
							tun.LearnNDP(dstip6, eth.SrcMAC)
							tun.logger.Debugf("received an NeighborAdvertisement, Neighbor learned")
							tun.DumpPacket(packetData)
							return 0, nil
						}
					}
				}
				n = copy(buf[offset:], packetData[14:])

			}
		}
	}
	return
}

func (tun *NativeTun) sendARPRequest(queueID uint8, srcIPv4 []byte, dstIPv4 []byte) error {
	// Set up all the layers' fields we can.
	eth := layers.Ethernet{
		SrcMAC:       tun.selfIfMacAddr.ToMAC(),
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(tun.selfIfMacAddr.ToMAC()),
		SourceProtAddress: srcIPv4,
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    dstIPv4,
	}
	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	// Send one packet for every address.

	gopacket.SerializeLayers(buf, opts, &eth, &arp)
	var response = buf.Bytes()

	_, err := tun.memif.TxBurst(queueID, []libmemif.RawPacketData{response})

	return err
}

func (tun *NativeTun) sendARPReply(queueID uint8, l2srcMac []byte, l2dstMac []byte, srcMAC []byte, srcIPv4 []byte, dstMAC []byte, dstIPv4 []byte) (err error) {
	ethResp := layers.Ethernet{
		SrcMAC:       l2srcMac, //hwAddr,
		DstMAC:       l2dstMac, //eth.SrcMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	arpResp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   srcMAC,  //[]byte(hwAddr),
		SourceProtAddress: srcIPv4, //[]byte(arp.DstProtAddress),
		DstHwAddress:      dstMAC,  //eth.SrcMAC,
		DstProtAddress:    dstIPv4, //arp.SourceProtAddress,
	}
	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err = gopacket.SerializeLayers(buf, opts, &ethResp, &arpResp)
	if err != nil {
		tun.logger.Errorf("SerializeLayers error: ", err)
		return err
	}
	var response = buf.Bytes()
	_, err = tun.memif.TxBurst(queueID, []libmemif.RawPacketData{response})
	return nil
}

func (tun *NativeTun) sendNDNS(queueID uint8, l3srcIP []byte, nstrg net.IP) error {
	var l2srcMac = tun.selfIfMacAddr.ToMAC()
	var nstrgbyte = nstrg.To16()
	var l2dstMac = []byte{0x33, 0x33, 0xff, nstrgbyte[13], nstrgbyte[14], nstrgbyte[15]}
	var l3dstIP = append([]byte{0xff, 0x2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, l2dstMac[2:6]...)
	var nsData = l2srcMac
	ethResp := layers.Ethernet{
		SrcMAC:       l2srcMac, //hwAddr,
		DstMAC:       l2dstMac, //eth.SrcMAC,
		EthernetType: layers.EthernetTypeIPv6,
	}
	ipResp := layers.IPv6{
		Version:    ipv6.Version,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   255,
		SrcIP:      l3srcIP, //icmp.TargetAddress,
		DstIP:      l3dstIP, //ip.SrcIP,
	}
	icmpResp := layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborSolicitation, 0),
	}
	icmpnsResp := layers.ICMPv6NeighborSolicitation{
		TargetAddress: nstrg, //icmp.TargetAddress,
		Options: []layers.ICMPv6Option{
			{
				Type: layers.ICMPv6OptSourceAddress,
				Data: nsData, //tun.selfIfMacAddr.ToMAC(),
			},
		},
	}
	err := icmpResp.SetNetworkLayerForChecksum(&ipResp)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err = gopacket.SerializeLayers(buf, opts, &ethResp, &ipResp, &icmpResp, &icmpnsResp)
	if err != nil {
		tun.logger.Errorf("SerializeLayers error: ", err)
		return err
	}
	var response = buf.Bytes()
	_, err = tun.memif.TxBurst(queueID, []libmemif.RawPacketData{response})
	return nil
}

func (tun *NativeTun) sendNDNA(queueID uint8, l2srcMac []byte, l2dstMac []byte, l3srcIP net.IP, l3DstIP net.IP, natrg net.IP, naData []byte) (err error) {

	ethResp := layers.Ethernet{
		SrcMAC:       l2srcMac, //hwAddr,
		DstMAC:       l2dstMac, //eth.SrcMAC,
		EthernetType: layers.EthernetTypeIPv6,
	}
	ipResp := layers.IPv6{
		Version:    ipv6.Version,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   255,
		SrcIP:      l3srcIP, //icmp.TargetAddress,
		DstIP:      l3DstIP, //ip.SrcIP,
	}
	icmpResp := layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborAdvertisement, 0),
	}
	icmpnaResp := layers.ICMPv6NeighborAdvertisement{
		Flags:         0x60,
		TargetAddress: natrg, //icmp.TargetAddress,
		Options: []layers.ICMPv6Option{
			{
				Type: layers.ICMPv6OptTargetAddress,
				Data: naData, //tun.selfIfMacAddr.ToMAC(),
			},
		},
	}
	err = icmpResp.SetNetworkLayerForChecksum(&ipResp)
	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err = gopacket.SerializeLayers(buf, opts, &ethResp, &ipResp, &icmpResp, &icmpnaResp)
	if err != nil {
		tun.logger.Errorf("SerializeLayers error: ", err)
		return err
	}
	var response = buf.Bytes()
	_, err = tun.memif.TxBurst(queueID, []libmemif.RawPacketData{response})
	return nil
}

func (tun *NativeTun) Events() chan Event {
	return tun.events
}

func (tun *NativeTun) Close() error {
	// connect to VPP
	conn, err := govpp.Connect(vppApiSocketPath)
	if err != nil {
		log.Fatalln("ERROR: connecting to VPP failed:", err)
	}
	defer conn.Disconnect()

	// create a channel
	ch, err := conn.NewAPIChannel()
	if err != nil {
		log.Fatalln("ERROR: creating channel failed:", err)
	}
	defer ch.Close()

	memifservice := memif.NewServiceClient(conn)

	tun.events <- EventDown
	tun.memif.Close()
	libmemif.Cleanup()

	// delete interface memif memif1/1
	_, err = memifservice.MemifDelete(context.Background(), &memif.MemifDelete{
		SwIfIndex: tun.SwIfIndex,
	})
	// delete memif socket id 1
	_, err = memifservice.MemifSocketFilenameAddDel(context.Background(), &memif.MemifSocketFilenameAddDel{
		IsAdd:          false,
		SocketID:       tun.ifid,
		SocketFilename: tun.memifSockPath,
	})
	close(tun.errors)

	return nil
}

func (tun *NativeTun) routineNetlinkListener() {
	tun.events <- EventUp
	select {
	case <-tun.statusListenersShutdown:
		return
	}
}

func CreateTUN(name string, mtu int) (Device, error) {

	if os.Getenv(ENV_VPP_MEMIF_SOCKET_DIR) != "" {
		vppMemifSocketDir = os.Getenv(ENV_VPP_MEMIF_SOCKET_DIR)
	}
	if os.Getenv(ENV_VPP_MEMIF_CONFIG_DIR) != "" {
		vppMemifConfigDir = os.Getenv(ENV_VPP_MEMIF_CONFIG_DIR)
	}
	if os.Getenv(ENV_VPP_SOCKET_PATH) != "" {
		vppApiSocketPath = os.Getenv(ENV_VPP_SOCKET_PATH)
	}

	if err := os.MkdirAll(vppMemifSocketDir, 0755); err != nil {
		return nil, err
	}

	byteValue, err := ioutil.ReadFile(path.Join(vppMemifConfigDir, name+".json"))
	if err != nil {
		return nil, err
	}

	ifConfig := InterfaceConfig{}

	err = json.Unmarshal(byteValue, &ifConfig)
	if err != nil {
		return nil, err
	}

	if ifConfig.Uid == 0 {
		ifConfig.Uid = rand.Uint32()
	}

	if ifConfig.VppBridgeID == 0 {
		ifConfig.VppBridgeID = vppBridgeID
	}

	// connect to VPP
	conn, err := govpp.Connect(vppApiSocketPath)
	if err != nil {
		log.Fatalln("ERROR: connecting to VPP failed:", err)
	}
	defer conn.Disconnect()

	// create a channel
	ch, err := conn.NewAPIChannel()
	if err != nil {
		log.Fatalln("ERROR: creating channel failed:", err)
	}
	defer ch.Close()

	if err := ch.CheckCompatiblity(&memif.MemifSocketFilenameAddDel{}, &memif.MemifCreate{}, &memif.MemifDelete{}); err != nil {
		return nil, err
	}
	if err := ch.CheckCompatiblity(&interfaces.SwInterfaceSetFlags{}); err != nil {
		return nil, err
	}
	if err := ch.CheckCompatiblity(&l2.L2fibAddDel{}, &l2.SwInterfaceSetL2Bridge{}); err != nil {
		return nil, err
	} /*
		if err := ch.CheckCompatiblity(ip_neighbor.AllMessages()...); err != nil {
			return nil, err
		}*/

	memifservice := memif.NewServiceClient(conn)
	interfacservice := interfaces.NewServiceClient(conn)
	l2service := l2.NewServiceClient(conn)
	//ip_neighborservice := ip_neighbor.NewServiceClient(conn)

	// MAC address for vpp l2 interface

	idbuf := make([]byte, 4)
	binary.BigEndian.PutUint32(idbuf, ifConfig.Uid)

	gwMacAddr, err := net.ParseMAC(ifConfig.GateWayMacAddr)
	if err != nil {
		gwMacAddr, _ = net.ParseMAC(defaultGwMacAddr)
	}

	thelogger := logger.New()
	thelogger.Out = os.Stdout
	thelogger.Level = func() logger.Level {
		switch os.Getenv("LOG_LEVEL") {
		case "verbose", "debug":
			return logger.DebugLevel
		case "error":
			return logger.ErrorLevel
		case "silent":
			return logger.PanicLevel
		}
		return logger.ErrorLevel
	}()

	libmemif.SetLogger(thelogger)

	tun := &NativeTun{
		name:                    name,
		memifSockPath:           path.Join(vppMemifSocketDir, name+".sock"),
		selfIfMacAddr:           ethernet_types.MacAddress{0x0a, 0x42, idbuf[0], idbuf[1], idbuf[2], idbuf[3]},
		vppIfMacAddr:            ethernet_types.MacAddress{0x0b, 0x42, idbuf[0], idbuf[1], idbuf[2], idbuf[3]},
		gwMacAddr:               gwMacAddr,
		selfIPv4ARPTable:        make(map[[4]byte]net.HardwareAddr),
		selfIPv4ARPTime:         make(map[[4]byte]int64),
		selfIPv6NeiTable:        make(map[[16]byte]net.HardwareAddr),
		selfIPv6NeiTime:         make(map[[16]byte]int64),
		ifid:                    ifConfig.Uid,
		tempMTU:                 9000,
		logger:                  thelogger,
		events:                  make(chan Event, 5),
		errors:                  make(chan error, 5),
		statusListenersShutdown: make(chan struct{}),
	}

	for _, ipv4str := range ifConfig.IPv4ArpResponseRanges {
		the_ipv4, the_ipv4net, err := net.ParseCIDR(ipv4str)
		if err != nil {
			return nil, err
		}
		if the_ipv4.To4() == nil {
			return nil, errors.New("Not a valid IPv4 CIDR")
		}
		tun.selfIPv4ARPRspRanges = append(tun.selfIPv4ARPRspRanges, *the_ipv4net)
	}
	for _, ipv6str := range ifConfig.IPv6NdpNeighAdvRanges {
		the_ipv6, the_ipv6net, err := net.ParseCIDR(ipv6str)
		if err != nil {
			return nil, err
		}
		if the_ipv6.To16() == nil {
			return nil, errors.New("Not a valid IPv6 CIDR")
		}
		tun.selfIPv6NDPRspRanges = append(tun.selfIPv6NDPRspRanges, *the_ipv6net)
	}

	for _, ipv4str := range ifConfig.IPv4ArpLearningRanges {
		the_ipv4, the_ipv4net, err := net.ParseCIDR(ipv4str)
		if err != nil {
			return nil, err
		}
		if the_ipv4.To4() == nil {
			return nil, errors.New("Not a valid IPv4 CIDR")
		}
		tun.selfIPv4ARPLrnRanges = append(tun.selfIPv4ARPLrnRanges, *the_ipv4net)
	}
	for _, ipv6str := range ifConfig.IPv6NdpLearningRanges {
		the_ipv6, the_ipv6net, err := net.ParseCIDR(ipv6str)
		if err != nil {
			return nil, err
		}
		if the_ipv6.To16() == nil {
			return nil, errors.New("Not a valid IPv6 CIDR")
		}
		tun.selfIPv6NDPLrnRanges = append(tun.selfIPv6NDPLrnRanges, *the_ipv6net)
	}

	// create memif socket id 1 filename /tmp/icmp-responder-example

	_, err = memifservice.MemifSocketFilenameAddDel(context.Background(), &memif.MemifSocketFilenameAddDel{
		IsAdd:          true,
		SocketID:       tun.ifid,
		SocketFilename: tun.memifSockPath,
	})
	if err != nil {
		return nil, err
	}

	// create interface memif id 1 socket-id 1 slave secret secret no-zero-copy

	memifCreateReply, err := memifservice.MemifCreate(context.Background(), &memif.MemifCreate{
		Role:       memif.MEMIF_ROLE_API_SLAVE,
		Mode:       memif.MEMIF_MODE_API_ETHERNET,
		RxQueues:   NumQueues, // MEMIF_DEFAULT_RX_QUEUES
		TxQueues:   NumQueues, // MEMIF_DEFAULT_TX_QUEUES
		ID:         tun.ifid,
		SocketID:   tun.ifid,
		RingSize:   1024, // MEMIF_DEFAULT_RING_SIZE
		BufferSize: 2048, // MEMIF_DEFAULT_BUFFER_SIZE 2048
		NoZeroCopy: true,
		HwAddr:     tun.vppIfMacAddr,
		Secret:     ifConfig.Secret,
	})

	if err != nil {
		return nil, err
	}

	tun.SwIfIndex = memifCreateReply.SwIfIndex

	// set int state memif1/1 up

	_, err = interfacservice.SwInterfaceSetFlags(context.Background(), &interfaces.SwInterfaceSetFlags{
		SwIfIndex: tun.SwIfIndex,
		Flags:     interface_types.IF_STATUS_API_FLAG_ADMIN_UP,
	})
	if err != nil {
		return nil, err
	}

	//l2fib add aa:aa:aa:aa:aa:aa 4242 memif1/1 static
	_, err = l2service.L2fibAddDel(context.Background(), &l2.L2fibAddDel{
		Mac:       tun.selfIfMacAddr,
		BdID:      ifConfig.VppBridgeID,
		SwIfIndex: tun.SwIfIndex,
		IsAdd:     true,
		StaticMac: false,
		FilterMac: false,
		BviMac:    false,
	})

	//set interface l2 bridge memif1/1 4242
	_, err = l2service.SwInterfaceSetL2Bridge(context.Background(), &l2.SwInterfaceSetL2Bridge{
		RxSwIfIndex: tun.SwIfIndex,
		BdID:        ifConfig.VppBridgeID,
		PortType:    l2.L2_API_PORT_TYPE_NORMAL,
		Shg:         0,
		Enable:      true,
	})

	//init libmemif
	libmemif.Init(tun.name)
	onConnectWg.Add(1)
	memifCallbacks := &libmemif.MemifCallbacks{
		OnConnect:    OnConnect,
		OnDisconnect: OnDisconnect,
	}

	// Prepare memif1 configuration.
	memifConfig := &libmemif.MemifConfig{
		MemifMeta: libmemif.MemifMeta{
			IfName:         tun.name,
			ConnID:         tun.ifid,
			SocketFilename: tun.memifSockPath,
			Secret:         tun.secret,
			IsMaster:       true,
			Mode:           libmemif.IfModeEthernet,
		},
		MemifShmSpecs: libmemif.MemifShmSpecs{
			NumRxQueues:  NumQueues,
			NumTxQueues:  NumQueues,
			BufferSize:   2048,
			Log2RingSize: 10,
		},
	}

	// Create memif1 interface.
	memif, err := libmemif.CreateInterface(memifConfig, memifCallbacks)
	if err != nil {
		tun.logger.Errorf("libmemif.CreateInterface() error: %v\n", err)
		return nil, err
	}

	onConnectWg.Wait()
	tun.memif = memif
	details, err := memif.GetDetails()
	tun.RxQueues = len(details.RxQueues)
	tun.RxintCh = memif.GetInterruptChan()
	tun.RxintErrCh = memif.GetInterruptErrorChan()
	tun.TxQueues = len(details.TxQueues)
	go func() { tun.events <- EventUp }()

	return tun, nil
}

// OnConnect is called when a memif connection gets established.
func OnConnect(memif *libmemif.Memif) (err error) {
	details, err := memif.GetDetails()
	if err != nil {
		fmt.Printf("libmemif.GetDetails() error: %v\n", err)
	}
	fmt.Printf("memif %s has been connected: %+v\n", memif.IfName, details)

	onConnectWg.Done()

	return nil
}

// OnDisconnect is called when a memif connection is lost.
func OnDisconnect(memif *libmemif.Memif) (err error) {
	fmt.Printf("memif %s has been disconnected\n", memif.IfName)
	return nil
}

func CreateTUNFromFile(file *os.File, mtu int) (Device, error) {
	return nil, errors.New("Not imelement in vpp")
}
