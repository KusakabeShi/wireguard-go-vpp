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
	crypto_rand "crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	math_rand "math/rand"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"git.fd.io/govpp.git"
	"git.fd.io/govpp.git/adapter/socketclient"
	"git.fd.io/govpp.git/binapi/ethernet_types"
	"git.fd.io/govpp.git/binapi/fib_types"
	interfaces "git.fd.io/govpp.git/binapi/interface"
	"git.fd.io/govpp.git/binapi/interface_types"
	"git.fd.io/govpp.git/binapi/ip"
	"git.fd.io/govpp.git/binapi/ip_neighbor"
	"git.fd.io/govpp.git/binapi/ip_types"
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

	//internal
	NumQueues       = uint8(1)
	ARP_NS_cooldown = int64(3)
	onConnectWg     sync.WaitGroup
	tunErrorChannel chan error
	thelogger       *logger.Logger

	ifConfig InterfaceConfig
	gwConfig GatewayConfig
)

type OperOnIp struct {
	IPv4   bool
	IPv6   bool
	IPv6LL bool `json:"IPv6 link-local"`
}

type GatewayConfig struct {
	GatewayMacAddr                     string
	WgIfMacaddrPrefix                  string // Macaddr = [prefix]:[uid]
	VppIfMacaddrPrefix                 string
	VppBridgeLoop_SwIfName             string
	VppBridgeLoop_SwIfIndex            interface_types.InterfaceIndex
	VppBridgeLoop_VppctlBinary         string // "vppctl"
	VppBridgeLoop_InstallMethod        string // "none" "api" "vppctl"
	VppBridgeLoop_InstallNeighbor      OperOnIp
	VppBridgeLoop_InstallNeighbor_Flag struct {
		Static     bool `json:"static"`
		NoFibEntry bool `json:"no-fib-entry"`
	}
	VppBridgeLoop_InstallRoutes         OperOnIp
	VppBridgeLoop_CheckRouteConflict    bool
	VppBridgeLoop_CheckRouteConfigPaths []string
}

type InterfaceConfig struct {
	Uid          uint32
	Secret       string
	Macaddr      string //Overwrite gwConfig.WgIfMacaddrPrefix
	vppIfMacAddr string

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
	ifuid                uint32
	SwIfIndex            interface_types.InterfaceIndex
	VppBridgeID          uint32
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
	if err := ch.CheckCompatiblity(&interfaces.SwInterfaceSetMtu{}); err != nil {
		return err
	}
	interfacservice := interfaces.NewServiceClient(conn)
	// set int state memif1/1 up

	_, err = interfacservice.SwInterfaceSetMtu(context.Background(), &interfaces.SwInterfaceSetMtu{
		SwIfIndex: tun.SwIfIndex,
		Mtu:       []uint32{uint32(n)},
	})
	if err != nil {
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
			tun.logger.Errorf("Dest not reachable: " + net.IP(dstIPv6[:]).String())
			return tun.gwMacAddr, errors.New("Dest not reachable: " + net.IP(dstIPv6[:]).String())
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
			tun.logger.Errorf("Dest not reachable: " + net.IP(dstIPv4[:]).String())
			return tun.gwMacAddr, errors.New("Dest not reachable: " + net.IP(dstIPv4[:]).String())
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
func (tun *NativeTun) DumpPacket(title string, packetData libmemif.RawPacketData) {
	tun.logger.Debugf(title)
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
				tun.DumpPacket("#############Packet Received############", packetData)
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
				tun.DumpPacket("#############Packet Received############", packetData)
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
					tun.DumpPacket("#############Packet Received############", packetData)
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
								return 0, nil
							}
						}
					}
				} else if len(packetData) == 86 && bytes.Equal(packetData[12:14], []byte{0x86, 0xdd}) && packetData[20] == 58 && packetData[54] == 136 {
					// 86dd: ipv6 / 58: icmpv6  / 135: neighbor adv
					tun.DumpPacket("#############Packet Received############", packetData)
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
	tun.DumpPacket("#############Packet Sent############", response)

	_, err := tun.memif.TxBurst(queueID, []libmemif.RawPacketData{response})

	return err
}

func b2uint8(mybool bool) uint8 {
	if mybool {
		return 1
	}
	return 0 //you just saved youself an else here!
}

func (tun *NativeTun) sendARPReply(queueID uint8, l2srcMac []byte, l2dstMac []byte, srcMAC []byte, srcIPv4 []byte, dstMAC []byte, dstIPv4 []byte) (err error) {
	ethResp := layers.Ethernet{
		SrcMAC:       l2srcMac, //hwAddr,
		DstMAC:       l2dstMac, //eth.SrcMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	if bytes.Equal(dstIPv4, []byte{0, 0, 0, 0}) {
		copy(dstIPv4, srcIPv4) // Gratuitous ARP
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
	tun.DumpPacket("#############Packet Sent############", response)
	_, err = tun.memif.TxBurst(queueID, []libmemif.RawPacketData{response})

	if gwConfig.VppBridgeLoop_InstallNeighbor.IPv4 == false {
		return err //Skip
	}
	switch gwConfig.VppBridgeLoop_InstallMethod {
	case "api":
		{
			// connect to VPP
			conn, err := govpp.Connect(vppApiSocketPath)
			if err != nil {
				log.Fatalln("ERROR: connecting to VPP failed:", err)
				return err
			}
			defer conn.Disconnect()

			// create a channel
			ch, err := conn.NewAPIChannel()
			if err != nil {
				log.Fatalln("ERROR: creating channel failed:", err)
				return err
			}
			defer ch.Close()
			var srcIPv4_fix16 [16]byte
			copy(srcIPv4_fix16[:], srcIPv4)
			ip_neighborservice := ip_neighbor.NewServiceClient(conn)
			_, err = ip_neighborservice.IPNeighborAddDel(context.Background(), &ip_neighbor.IPNeighborAddDel{
				IsAdd: true,
				Neighbor: ip_neighbor.IPNeighbor{
					SwIfIndex:  interface_types.InterfaceIndex(gwConfig.VppBridgeLoop_SwIfIndex),
					Flags:      ip_neighbor.IPNeighborFlags(uint8(ip_neighbor.IP_API_NEIGHBOR_FLAG_NO_FIB_ENTRY)*b2uint8(gwConfig.VppBridgeLoop_InstallNeighbor_Flag.NoFibEntry) | uint8(ip_neighbor.IP_API_NEIGHBOR_FLAG_STATIC)*b2uint8(gwConfig.VppBridgeLoop_InstallNeighbor_Flag.Static)),
					MacAddress: tun.selfIfMacAddr,
					IPAddress: ip_types.Address{
						Af: ip_types.ADDRESS_IP4,
						Un: ip_types.AddressUnion{srcIPv4_fix16},
					},
				},
			})
			return err
		}
	case "vppctl":
		{
			var IDs []string
			for _, i := range srcIPv4 {
				IDs = append(IDs, strconv.Itoa(int(i)))
			}

			exec_command := []string{"set", " ip", " neighbor"}
			exec_command = append(exec_command, gwConfig.VppBridgeLoop_SwIfName, strings.Join(IDs, "."), tun.selfIfMacAddr.ToMAC().String())
			if gwConfig.VppBridgeLoop_InstallNeighbor_Flag.Static {
				exec_command = append(exec_command, "static")
			}
			if gwConfig.VppBridgeLoop_InstallNeighbor_Flag.NoFibEntry {
				exec_command = append(exec_command, "no-fib-entry")
			}
			tun.logger.Debugf(gwConfig.VppBridgeLoop_VppctlBinary + " " + strings.Join(exec_command, " "))
			out, err := exec.Command(gwConfig.VppBridgeLoop_VppctlBinary, exec_command...).Output()
			if err == nil {
				tun.logger.Debug(string(out))
			} else {
				tun.logger.Error(err)
			}
			return err
		}
	}
	return err
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
	tun.DumpPacket("#############Packet Sent############", response)
	_, err = tun.memif.TxBurst(queueID, []libmemif.RawPacketData{response})
	return err
}

func isLinkLocal(ip net.IP) bool {
	_, ll, _ := net.ParseCIDR("fe80::0/10")
	return ll.Contains(ip)
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
	tun.DumpPacket("#############Packet Sent############", response)
	_, err = tun.memif.TxBurst(queueID, []libmemif.RawPacketData{response})

	if gwConfig.VppBridgeLoop_InstallNeighbor.IPv6LL && isLinkLocal(natrg) {
		// install neighbor
	} else if gwConfig.VppBridgeLoop_InstallNeighbor.IPv6 && !isLinkLocal(natrg) {
		// install neighbor
	} else {
		return err // Skip
	}
	switch gwConfig.VppBridgeLoop_InstallMethod {
	case "api":
		{
			// connect to VPP
			conn, err := govpp.Connect(vppApiSocketPath)
			if err != nil {
				log.Fatalln("ERROR: connecting to VPP failed:", err)
				return err
			}
			defer conn.Disconnect()

			// create a channel
			ch, err := conn.NewAPIChannel()
			if err != nil {
				log.Fatalln("ERROR: creating channel failed:", err)
				return err
			}
			defer ch.Close()
			var srcIPv6_fix16 [16]byte
			copy(srcIPv6_fix16[:], natrg.To16())
			ip_neighborservice := ip_neighbor.NewServiceClient(conn)
			_, err = ip_neighborservice.IPNeighborAddDel(context.Background(), &ip_neighbor.IPNeighborAddDel{
				IsAdd: true,
				Neighbor: ip_neighbor.IPNeighbor{
					SwIfIndex:  gwConfig.VppBridgeLoop_SwIfIndex,
					Flags:      ip_neighbor.IPNeighborFlags(uint8(ip_neighbor.IP_API_NEIGHBOR_FLAG_NO_FIB_ENTRY)*b2uint8(gwConfig.VppBridgeLoop_InstallNeighbor_Flag.NoFibEntry) | uint8(ip_neighbor.IP_API_NEIGHBOR_FLAG_STATIC)*b2uint8(gwConfig.VppBridgeLoop_InstallNeighbor_Flag.Static)),
					MacAddress: tun.selfIfMacAddr,
					IPAddress: ip_types.Address{
						Af: ip_types.ADDRESS_IP6,
						Un: ip_types.AddressUnion{srcIPv6_fix16},
					},
				},
			})
			return err
		}
	case "vppctl":
		{
			var IDs []string
			for _, i := range natrg.To16() {
				IDs = append(IDs, strconv.Itoa(int(i)))
			}

			exec_command := []string{"set", " ip", " neighbor"}
			exec_command = append(exec_command, gwConfig.VppBridgeLoop_SwIfName, natrg.String(), tun.selfIfMacAddr.ToMAC().String())
			if gwConfig.VppBridgeLoop_InstallNeighbor_Flag.Static {
				exec_command = append(exec_command, "static")
			}
			if gwConfig.VppBridgeLoop_InstallNeighbor_Flag.NoFibEntry {
				exec_command = append(exec_command, "no-fib-entry")
			}
			tun.logger.Debugf(gwConfig.VppBridgeLoop_VppctlBinary + " " + strings.Join(exec_command, " "))
			out, err := exec.Command(gwConfig.VppBridgeLoop_VppctlBinary, exec_command...).Output()
			if err == nil {
				tun.logger.Debug(string(out))
			} else {
				tun.logger.Error(err)
			}
			return err
		}
	}
	return err
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
	IPService := ip.NewServiceClient(conn)

	tun.events <- EventDown
	tun.memif.Close()
	libmemif.Cleanup()

	//ip route add 172.22.77.33/32 via loop42 0.0.0.0
	if gwConfig.VppBridgeLoop_InstallRoutes.IPv4 {
		for _, the_ip4 := range tun.selfIPv4ARPRspRanges {
			err = tun.RouteAddDel(IPService, the_ip4, 4, false, 32)
			if err != nil {
				tun.logger.Error(err)
			}
		}
	}
	if gwConfig.VppBridgeLoop_InstallRoutes.IPv6 || gwConfig.VppBridgeLoop_InstallRoutes.IPv6LL {
		for _, the_ip6 := range tun.selfIPv6NDPRspRanges {
			if isLinkLocal(the_ip6.IP) && gwConfig.VppBridgeLoop_InstallRoutes.IPv6LL {
			} else if gwConfig.VppBridgeLoop_InstallRoutes.IPv6 && !isLinkLocal(the_ip6.IP) {
			} else {
				continue
			}
			err = tun.RouteAddDel(IPService, the_ip6, 6, false, 128)
			if err != nil {
				tun.logger.Error(err)
			}
		}
	}

	// delete interface memif memif1/1
	_, err = memifservice.MemifDelete(context.Background(), &memif.MemifDelete{
		SwIfIndex: tun.SwIfIndex,
	})
	// delete memif socket id 1
	_, err = memifservice.MemifSocketFilenameAddDel(context.Background(), &memif.MemifSocketFilenameAddDel{
		IsAdd:          false,
		SocketID:       tun.ifuid,
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

func prefixStr2prefix(prefix string) ([]uint8, uint32, error) {
	hexStrs := strings.Split(strings.ToLower(prefix), ":")
	retprefix := make([]uint8, len(hexStrs))
	maxID := uint32(1)<<((6-len(hexStrs))*8) - 1
	if len(hexStrs) < 2 || len(hexStrs) > 5 {
		return []uint8{}, 0, errors.New("Macaddr prefix length must between 2 and 5, " + prefix + " is " + strconv.Itoa(len(hexStrs)))
	}
	for index, hexstr := range hexStrs {
		value, err := strconv.ParseInt(hexstr, 16, 16)
		if err != nil {
			return []uint8{}, 0, err
		}
		if index == 0 && value%2 != 0 {
			return []uint8{}, 0, errors.New("Can't use multicast mac address, the first byte of your mac address(" + hexstr + ") must be an even number")
		}
		retprefix[index] = uint8(value)
	}
	return retprefix, maxID, nil
}

func checkRouteOverlap(configFolders []string, targetConfigPath string) error {
	targetConfig := &InterfaceConfig{}
	targetIPv4ARPRspRanges := []net.IPNet{}
	targetIPv6NeiRspRanges := []net.IPNet{}
	byteValue, err := ioutil.ReadFile(targetConfigPath)
	if err != nil {
		return err
	}
	err = json.Unmarshal(byteValue, &targetConfig)
	if err != nil {
		return err
	}
	for _, ipv4str := range targetConfig.IPv4ArpResponseRanges {
		the_ipv4, the_ipv4net, err := net.ParseCIDR(ipv4str)
		if err != nil {
			return err
		}
		if the_ipv4.To4() == nil {
			return errors.New(targetConfigPath + ": Not a valid IPv4 CIDR: " + ipv4str)
		}
		targetIPv4ARPRspRanges = append(targetIPv4ARPRspRanges, *the_ipv4net)
	}
	for _, ipv6str := range targetConfig.IPv6NdpNeighAdvRanges {
		the_ipv6, the_ipv6net, err := net.ParseCIDR(ipv6str)
		if err != nil {
			return err
		}
		if the_ipv6.To16() == nil || strings.Contains(ipv6str, ".") {
			return errors.New(targetConfigPath + ": Not a valid IPv6 CIDR: " + ipv6str)
		}
		targetIPv6NeiRspRanges = append(targetIPv6NeiRspRanges, *the_ipv6net)
	}

	//////////
	checklist := []string{}
	for _, configFolder := range configFolders {
		err = filepath.Walk(configFolder,
			func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() == false {
					if strings.HasPrefix(info.Name(), "if.") && strings.HasSuffix(info.Name(), ".json") && targetConfigPath != path {
						checklist = append(checklist, path)
					}
				}
				return nil
			})
		if err != nil {
			return err
		}
	}
	for _, configPath := range checklist {
		//read json
		checkConfig := &InterfaceConfig{}
		checkIPv4ARPRspRanges := []net.IPNet{}
		checkIPv6NeiRspRanges := []net.IPNet{}
		byteValue, err := ioutil.ReadFile(configPath)
		if err != nil {
			return err
		}
		err = json.Unmarshal(byteValue, &checkConfig)
		if err != nil {
			return err
		}
		if targetConfig.VppBridgeID != checkConfig.VppBridgeID {
			continue
		}

		for _, ipv4str := range checkConfig.IPv4ArpResponseRanges {
			the_ipv4, the_ipv4net, err := net.ParseCIDR(ipv4str)
			if err != nil {
				return err
			}
			if the_ipv4.To4() == nil {
				return errors.New(configPath + ": Not a valid IPv4 CIDR: " + ipv4str)
			}
			checkIPv4ARPRspRanges = append(checkIPv4ARPRspRanges, *the_ipv4net)
		}
		for _, ipv6str := range checkConfig.IPv6NdpNeighAdvRanges {
			the_ipv6, the_ipv6net, err := net.ParseCIDR(ipv6str)
			if err != nil {
				return err
			}
			if the_ipv6.To16() == nil || strings.Contains(ipv6str, ".") {
				return errors.New(configPath + ": Not a valid IPv6 CIDR: " + ipv6str)
			}
			checkIPv6NeiRspRanges = append(checkIPv6NeiRspRanges, *the_ipv6net)
		}

		for _, targetIpv4 := range targetIPv4ARPRspRanges {
			for _, checkIpv4 := range checkIPv4ARPRspRanges {
				thelogger.Debugf("Check route overlap between [" + targetIpv4.String() + "] and [" + checkIpv4.String() + "]")
				if checkIpv4.Contains(targetIpv4.IP) || targetIpv4.Contains(checkIpv4.IP) {
					return errors.New("Network overlap detected at " + configPath + " with network [" + targetIpv4.String() + "] and [" + checkIpv4.String() + "]")
				}
			}
		}

		for _, targetIpv6 := range targetIPv6NeiRspRanges {
			for _, checkIpv6 := range checkIPv6NeiRspRanges {
				thelogger.Debugf("Check route overlap between [" + targetIpv6.String() + "] and [" + checkIpv6.String() + "]")
				if checkIpv6.Contains(targetIpv6.IP) || targetIpv6.Contains(checkIpv6.IP) {
					return errors.New("Network overlap detected at " + " and " + configPath + " with network [" + targetIpv6.String() + "] and [" + checkIpv6.String() + "]")
				}
			}
		}
	}
	return nil
}

func (tun *NativeTun) RouteAddDel(ipservice ip.RPCService, the_ip net.IPNet, version int, IsAdd bool, minlen int) error {
	the_ip_masklen, _ := the_ip.Mask.Size()
	the_ip_masklenu := uint8(the_ip_masklen)
	ipbits := 32
	if version == 6 {
		ipbits = 128
	}

	if ones, bits := the_ip.Mask.Size(); ones < minlen || bits != ipbits {
		return nil
	}
	the_ip_fixlen := [16]uint8{}
	Af := ip_types.ADDRESS_IP4
	FibProto := fib_types.FIB_API_PATH_NH_PROTO_IP4
	if version == 4 {
		copy(the_ip_fixlen[:], the_ip.IP.To4())
	} else if version == 6 {
		Af = ip_types.ADDRESS_IP6
		FibProto = fib_types.FIB_API_PATH_NH_PROTO_IP6
		copy(the_ip_fixlen[:], the_ip.IP.To16())
	} else {
		return errors.New("version mist be 4 or 6, received " + strconv.Itoa(version))
	}
	switch gwConfig.VppBridgeLoop_InstallMethod {
	case "api":
		{
			_, err := ipservice.IPRouteAddDel(context.Background(), &ip.IPRouteAddDel{
				IsAdd:       IsAdd,
				IsMultipath: true,
				Route: ip.IPRoute{
					TableID:    0,
					StatsIndex: 0,
					Prefix: ip_types.Prefix{
						Address: ip_types.Address{
							Af: Af,
							Un: ip_types.AddressUnion{the_ip_fixlen},
						},
						Len: the_ip_masklenu,
					},
					NPaths: 1,
					Paths: []fib_types.FibPath{
						{
							SwIfIndex:  uint32(gwConfig.VppBridgeLoop_SwIfIndex),
							TableID:    0,
							RpfID:      0,
							Weight:     1,
							Preference: 1,
							Type:       fib_types.FIB_API_PATH_TYPE_NORMAL,
							Flags:      fib_types.FIB_API_PATH_FLAG_NONE,
							Proto:      FibProto,
							Nh: fib_types.FibPathNh{
								Address:            ip_types.AddressUnion{the_ip_fixlen},
								ViaLabel:           0,
								ObjID:              0,
								ClassifyTableIndex: 0,
							},
							NLabels:    0,
							LabelStack: [16]fib_types.FibMplsLabel{},
						},
					},
				},
			})
			if err != nil {
				return err
			}
		}
	case "vppctl":
		{
			adddelstr := "del"
			if IsAdd {
				adddelstr = "add"
			}

			ipstr := the_ip.IP.String()
			exec_command := []string{"ip", "route", adddelstr, ipstr + "/" + strconv.Itoa(the_ip_masklen), "via", ipstr, gwConfig.VppBridgeLoop_SwIfName}
			tun.logger.Debugf(gwConfig.VppBridgeLoop_VppctlBinary + " " + strings.Join(exec_command, " "))
			out, err := exec.Command(gwConfig.VppBridgeLoop_VppctlBinary, exec_command...).Output()
			if err == nil {
				tun.logger.Debug(string(out))
			} else {
				tun.logger.Error(err)
			}
		}
	}
	return nil
}

func getRandUint32(max uint32) uint32 {
	randbyte := make([]byte, 4)
	randint := math_rand.Uint32()
	_, err := crypto_rand.Read(randbyte)
	if err != nil {
		return randint
	}
	randint = binary.BigEndian.Uint32(randbyte)
	if randint > max {
		randint = randint % max
	}
	return randint

}

func GetSwIfIndexByName(name string) (int, error) {
	exec_command := []string{"show", "interface", name}
	thelogger.Debugf(gwConfig.VppBridgeLoop_VppctlBinary + " " + strings.Join(exec_command, " "))
	out, err := exec.Command(gwConfig.VppBridgeLoop_VppctlBinary, exec_command...).Output()
	if err != nil {
		return 0, nil
	}
	outstr := string(out)
	outstrs := strings.Split(outstr, "\n")
	if len(outstrs) <= 1 {
		return 0, errors.New(outstr)
	}
	infoss := strings.Split(outstrs[1], " ")
	var infos []string
	for _, str := range infoss {
		if str != "" {
			infos = append(infos, str)
		}
	}
	if len(infos) <= 1 {
		return 0, errors.New(outstr)
	}
	return strconv.Atoi(infos[1])
}

func CreateTUN(name string, mtu int) (Device, error) {
	// Set logger
	thelogger = logger.New()
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
	math_rand.Seed(time.Now().UnixNano())
	// Make a Regex to say we only want letters and numbers
	// Remove strange characters from name
	regpattern, err := regexp.Compile("[^a-zA-Z0-9_\\-]+")
	if err != nil {
		log.Fatal(err)
	}
	name = regpattern.ReplaceAllString(name, "")
	// Read required path from env
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
	//read if.home.json
	byteValue, err := ioutil.ReadFile(path.Join(vppMemifConfigDir, "if."+name+".json"))
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(byteValue, &ifConfig)
	if err != nil {
		return nil, err
	}

	//read gw.4242.json and correct value
	byteValue, err = ioutil.ReadFile(path.Join(vppMemifConfigDir, "gw."+fmt.Sprint(ifConfig.VppBridgeID)+".json"))
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(byteValue, &gwConfig)
	if err != nil {
		return nil, err
	}
	if gwConfig.VppBridgeLoop_VppctlBinary == "" {
		gwConfig.VppBridgeLoop_VppctlBinary = "vppctl"
	}
	if gwConfig.VppBridgeLoop_SwIfIndex == 0 && gwConfig.VppBridgeLoop_InstallMethod == "api" {
		tempVppBridgeLoop_SwIfIndex, err := GetSwIfIndexByName(gwConfig.VppBridgeLoop_SwIfName)
		if err != nil {
			return nil, err
		}
		gwConfig.VppBridgeLoop_SwIfIndex = interface_types.InterfaceIndex(tempVppBridgeLoop_SwIfIndex)
	}

	err = checkRouteOverlap(gwConfig.VppBridgeLoop_CheckRouteConfigPaths, path.Join(vppMemifConfigDir, "if."+name+".json"))
	if err != nil {
		return nil, err
	}

	gwMacAddr, err := net.ParseMAC(gwConfig.GatewayMacAddr)
	if err != nil {
		return nil, err
	}

	// Generate MAC address for vpp interface at layer 2
	selfIfMacAddr := [6]byte{0x0a, 0x42, 0, 1, 2, 3}
	vppIfMacAddr := [6]byte{0x0c, 0x42, 0, 1, 2, 3}
	randUid := getRandUint32(math.MaxInt32)
	binary.BigEndian.PutUint32(selfIfMacAddr[2:], randUid)
	binary.BigEndian.PutUint32(vppIfMacAddr[2:], randUid)

	if ifConfig.vppIfMacAddr != "" && ifConfig.Macaddr != "" { // ifConfig Overwrite
		selfIfMacAddrvslice, err := net.ParseMAC(ifConfig.Macaddr)
		if err != nil {
			return nil, err
		}
		vppIfMacAddrslice, err := net.ParseMAC(ifConfig.vppIfMacAddr)
		if err != nil {
			return nil, err
		}
		copy(selfIfMacAddr[:], selfIfMacAddrvslice)
		copy(vppIfMacAddr[:], vppIfMacAddrslice)
	} else { //Generate by rule
		selfIfMacPrefix, maxIDwg, err := prefixStr2prefix(gwConfig.WgIfMacaddrPrefix)
		if err != nil {
			thelogger.Error("Prefix parse error: " + gwConfig.WgIfMacaddrPrefix)
			return nil, err
		}
		vppIfMacPrefix, maxIDvpp, err := prefixStr2prefix(gwConfig.VppIfMacaddrPrefix)
		if err != nil {
			thelogger.Error("Prefix parse error: " + gwConfig.WgIfMacaddrPrefix)
			return nil, err
		}

		if maxIDwg != maxIDvpp {
			return nil, errors.New("Length of WgIfMacaddrPrefix and VppIfMacaddrPrefix must be same")
		}

		if ifConfig.Uid == 0 {
			ifConfig.Uid = getRandUint32(maxIDwg)
		}
		if ifConfig.Uid > maxIDwg {
			return nil, errors.New("UID can't grater than 256^len(MacAddrPrefix) -1 = " + fmt.Sprint(maxIDwg))
		}

		idbuf := make([]byte, 4)
		binary.BigEndian.PutUint32(idbuf, ifConfig.Uid)
		copy(selfIfMacAddr[2:], idbuf)
		copy(vppIfMacAddr[2:], idbuf)

		copy(selfIfMacAddr[:], selfIfMacPrefix)
		copy(vppIfMacAddr[:], vppIfMacPrefix)

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
	}
	if err := ch.CheckCompatiblity(&ip_neighbor.IPNeighborAddDel{}); err != nil {
		return nil, err
	}
	if err := ch.CheckCompatiblity(&ip.IPRouteAddDel{}); err != nil {
		return nil, err
	}

	memifservice := memif.NewServiceClient(conn)
	interfacservice := interfaces.NewServiceClient(conn)
	l2service := l2.NewServiceClient(conn)
	ipservice := ip.NewServiceClient(conn)

	tun := &NativeTun{
		name:                    name,
		memifSockPath:           path.Join(vppMemifSocketDir, name+".sock"),
		selfIfMacAddr:           ethernet_types.MacAddress(selfIfMacAddr),
		vppIfMacAddr:            ethernet_types.MacAddress(vppIfMacAddr),
		gwMacAddr:               gwMacAddr,
		selfIPv4ARPTable:        make(map[[4]byte]net.HardwareAddr),
		selfIPv4ARPTime:         make(map[[4]byte]int64),
		selfIPv6NeiTable:        make(map[[16]byte]net.HardwareAddr),
		selfIPv6NeiTime:         make(map[[16]byte]int64),
		ifuid:                   ifConfig.Uid,
		VppBridgeID:             ifConfig.VppBridgeID,
		tempMTU:                 9000,
		logger:                  thelogger,
		events:                  make(chan Event, 5),
		errors:                  make(chan error, 5),
		statusListenersShutdown: make(chan struct{}),
	}

	tunErrorChannel = tun.errors
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
		if the_ipv6.To16() == nil || strings.Contains(ipv6str, ".") {
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
		SocketID:       tun.ifuid,
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
		ID:         tun.ifuid,
		SocketID:   tun.ifuid,
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

	//set interface l2 bridge memif1/1 4242
	_, err = l2service.SwInterfaceSetL2Bridge(context.Background(), &l2.SwInterfaceSetL2Bridge{
		RxSwIfIndex: tun.SwIfIndex,
		BdID:        ifConfig.VppBridgeID,
		PortType:    l2.L2_API_PORT_TYPE_NORMAL,
		Shg:         0,
		Enable:      true,
	})
	if err != nil {
		return nil, err
	}

	//ip route add 172.22.77.33/32 via loop42 0.0.0.0
	if gwConfig.VppBridgeLoop_InstallRoutes.IPv4 {
		for _, the_ip4 := range tun.selfIPv4ARPRspRanges {
			err = tun.RouteAddDel(ipservice, the_ip4, 4, true, 32)
			if err != nil {
				return nil, err
			}
		}
	}
	if gwConfig.VppBridgeLoop_InstallRoutes.IPv6 || gwConfig.VppBridgeLoop_InstallRoutes.IPv6LL {
		for _, the_ip6 := range tun.selfIPv6NDPRspRanges {
			if isLinkLocal(the_ip6.IP) && gwConfig.VppBridgeLoop_InstallRoutes.IPv6LL {
			} else if gwConfig.VppBridgeLoop_InstallRoutes.IPv6 && !isLinkLocal(the_ip6.IP) {
			} else {
				continue
			}
			err = tun.RouteAddDel(ipservice, the_ip6, 6, true, 128)
			if err != nil {
				return nil, err
			}
		}
	}
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
			ConnID:         tun.ifuid,
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
	if err != nil {
		tun.logger.Debug("BdID=" + fmt.Sprintf("%d", ifConfig.VppBridgeID))
		tun.logger.Debug("SwIfIndex=" + fmt.Sprintf("%d", tun.SwIfIndex))
		tun.logger.Error(err)
		//return nil, err
		//VPP can learn l2fib later if this command failed
	}
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
	tunErrorChannel <- errors.New(fmt.Sprintf("memif %s has been disconnected", memif.IfName))
	return nil
}

func CreateTUNFromFile(file *os.File, mtu int) (Device, error) {
	return nil, errors.New("Not implement in vpp")
}
