# Go Implementation of [WireGuard](https://www.wireguard.com/)

This is an implementation of WireGuard in Go, but connect to vpp by libmemif instead of use tun device in linux kernel.

## Environment Variables

	VPP_MEMIF_SOCKET_DIR
	VPP_MEMIF_CONFIG_DIR
	VPP_API_SOCKET_PATH


* VPP_API_SOCKET_PATH
    * default value: `/run/vpp/api.sock`
    * The api socket to connect to vpp
* VPP_MEMIF_SOCKET_DIR
    * default value: `/var/run/wggo-vpp`
    * The folder to put socket files to communicate between vpp and wggo-vpp
* VPP_MEMIF_CONFIG_DIR
    * Default value: `/etc/wggo-vpp`
    * The folder to put configs 

## Usage

### Setup VPP
You have to setup vpp before use the wireguard-go-vpp.  
Start VPP and run following command in `vppcli`

if you want to run it in userspace without any kernel feature, remember to set dpdk config to `"no-pci no-hugetlb"`

Remember to replace the `MAC address` / `Bridge ID` /`Instance ID` to what you want. In this case,

Instance ID=42  
VPPBridge ID=4242
MacAddr=42:42:42:42:42:42  
MTU=1500  

```
create loopback interface mac 42:42:42:42:42:42 instance 42
set int l2 bridge loop42 4242 bvi
set interface mtu 1500 loop42
set int state loop42 up
```

Setup your `IPv4` , `IPv6` and `IPv6 link-local` to interface `loop42`
```
set interface ip address loop42 10.127.111.1/8
set interface ip address loop42 fd10:127:e00f::1/10
set interface ip address loop42 fe80::aa:1111:1/128
```
Add custom route(Optional, but required on DN42 network)
```
ip route add 172.20.0.0/14 via 0.0.0.0 loop42
ip route add 172.31.0.0/16 via 0.0.0.0 loop42
```

These command above will create a interface named `loop42` with interface index `1`, you cam check it by this.
```
DBGvpp# show interface 
              Name               Idx    State  MTU (L3/IP4/IP6/MPLS)     Counter          Count     
local0                            0     down          0/0/0/0       
loop42                            1      up          1500/0/0/0     tx packets                    12
                                                                    tx bytes                    1160
                                                                    drops                          5
```
The name `loop42` and index `1` may be varied.  
You need to configure it to variable `VppBridgeLoop_SwIfName` and `VppBridgeLoop_SwIfIndex` in the following section.

### Interface Config

Similar to original wireguard-go, but you have to setup some extra config for the vpp-memif and layer2/layer3 conversion.

All config should put in `/etc/wggo-vp` (Changeable by environment variable `VPP_MEMIF_CONFIG_DIR`)

There are two config you need to setup, First config ```if.[name].json``` is a per-interface config.

In this case, I use `home` as the interface name. Change it to whatever you like.

Create a json file at `/etc/wggo-vpp/if.home.json` with following content:

```json
{
        "uid": 3,
        "secret": "some_secret",
        "IPv4ArpResponseRanges": [
                "172.22.77.33/32"
        ],
        "IPv6NdpNeighAdvRanges": [
                "fd28:cb8f:4c92::33/128","fe80::42:1817:1/128"
        ],
        "IPv4ArpLearningRanges": [  ],
        "IPv6NdpLearningRanges": [  ],
        "VppBridgeID": 4242
}
```

#### parameters
1. uid: Unique ID for vpp interface id, must be unique in the vpp runtime.
2. secret: the secret for the connection between vpp and wggo-vpp
3. IPv4ArpResponseRanges: 
    1. For `vpp -> wg` traffic within these ranges, it will reply an ARPReply if an ARP request packet received.
    2. Basically it's equal to announce **I have these IPs** in the LAN.
    3. Make sure **do not overlap** any IP at vpp side(like other wggo-vpp connect to same vpp bridge) otherwise it will cause IP conflict.
4. IPv4ArpLearningRanges(Optional): 
    1. For `vpp -> wg` traffic within these ranges, it will learn it's Mac Address to ARP table if an ARPReply packet received
    2. For `wg -> vpp` traffic within these ranges, wggo-vpp will lookup the MacAddr from ARP table instead of using `GateWayMacAddr` to fill the layer2 ethernet header. 
    3. If the lookup failed, it will send an ARP request and drop the original packet.
5. IPv6NdpNeighAdvRanges: Similar to `IPv4ArpResponseRanges`, but it replies Neighbor Advertisement if a Neighbor Solicitation received.
   1. If you add link-local address in this section, mask length must be `128` because VPP doesn't support ipv6 link-local with mask other than `/128`.
   2. You can add multiple `/128` link-local address in this section if you need.
6. IPv6NdpLearningRanges(Optional): Same as `IPv4ArpLearningRanges`, but it's IPv6 version.
7. VppBridgeID: VppBridge ID defined in previous section. We need to use this value in next section.

### Gateway config

Second config ```gw.[VppBridgeID].json``` is a the config shared among all interface using the same VppBridgeID.

Create a json file at `/etc/wggo-vpp/gw.4242.json` with following content:
```
{
   "GatewayMacAddr":"42:42:42:42:42:42",
   "WgIfMacaddrPrefix":"98:D2:93",
   "VppIfMacaddrPrefix":"A4:77:33",
   "VppBridgeLoop_InstallMethod":"api",
   "VppBridgeLoop_CheckRouteConflict":true,
   "VppBridgeLoop_CheckRouteConfigPaths":[
      "/etc/wggo-vpp"
   ],
   "VppBridgeLoop_VppctlBin":"vppctl",
   "VppBridgeLoop_SwIfName":"loop42",
   "VppBridgeLoop_SwIfIndex":1,
   "VppBridgeLoop_InstallNeighbor":{
      "IPv4":false,
      "IPv6":false,
      "IPv6 link-local":false
   },
   "VppBridgeLoop_InstallNeighbor_Flag":{
      "static":true,
      "no-fib-entry":false
   },
   "VppBridgeLoop_InstallRoutes":{
      "IPv4":true,
      "IPv6":false,
      "IPv6 link-local":true
   }
}
```
#### parameters
1. GatewayMacAddr: The MAC address of vpp bvi interface
2. WgIfMacaddrPrefix: 
    1. The MAC address prefix of the interface of wggo-vpp.
    2. The MAC address will be `[prefix]:[uid]`.
    3. Must be unique in the whole LAN (multiple VPP or bridging to another interface).
3. VppIfMacaddrPrefix: 
    1. The MAC address prefix of the interface of wggo-vpp at VPP side.
    2. Because this interface is bridged to VppBridgeID at vpp side, so it's useless but I think it's still better to be unique at the LAN.
4. VppBridgeLoop_CheckRouteConflict: It will read all configs to check whether there an overlap between the starting interface and other configs before interface startup. If there any overlap in `IPv4ArpResponseRanges` / `IPv6NdpNeighAdvRanges`, it will abort to start.
5. VppBridgeLoop_CheckRouteConfigPaths: All files(recursively) named with `if.*.json` in this folder will add to the checklist mentioned above.
6. VppBridgeLoop_InstallMethod: Indicate `wggo-vpp` how to install route table or arp-table to vpp.
   1. `none`: disable features below completely.
   2. `api`: use APIs from govpp to interact with vpp
   3. `vppctl`: use external command by `exec.Command()` to interact with vpp
7. VppBridgeLoop_VppctlBin: Binary name/path of `vppctl`, default: `vppctl`
8. VppBridgeLoop_SwIfName: Interface name of the BVI interface. Required if InstallMode=`vppctl`
9. VppBridgeLoop_SwIfIndex: Interface index og the BVI interface. Required if InstallMode = `api`. 
   1. If it were set to `0`, it will lookup it automatically by `vppctl` with command `vppctl show interface [name]`
   2. **I have no idea how to use APIs from govpp to lookup the index by name**, so I use vppctl to retrieve interface index from VPP. If **anyone knows how to do it, please contact me** or submit it in issue, thanks.
10. VppBridgeLoop_InstallNeighbor: It will install the arp entry to VPP via `api` or `vppctl` when ARPReply send to VPP. 
    1.  Add ARP entry in VPP also add a /32 or /128 route implicitly.
    2.  Which is required in VPP to make IP reachable in custom routes not covered by IP/subnet of any interface.
    3.  You may don't need this if you use `VppBridgeLoop_InstallRoutes`, but it's safe to use both.
11. VppBridgeLoop_InstallNeighbor_Flag: The flag for the ARP entry in VPP.
12. VppBridgeLoop_InstallRoutes: Install all subnets from `IPv4ArpResponseRanges` and `IPv6NdpNeighAdvRanges` to VPP route table.
    1. For custom routes not covered by IP/subnet of any interface, nexthop IP is required. 
    2. Any `/32(IPv4)` and `/128(IPv6)` routes adds nexthop implicitly, so our custom routes installed in `Setup VPP` section will not work property until we use this feature.
    3. So I add this feature, install required `/32(IPv4)` and `/128(IPv6)` routes at startup.
    4. You may don't need this if you use `VppBridgeLoop_InstallNeighbor`, but it's safe to use both.
    5. Only `/32(IPv4)` and `/128(IPv6)` routes will be installed, you can remove this check by modify my source code. But I didn't check if it works.


While the JSON configured, you can run wireguard-go-vpp via following command:

```
$ wireguard-go-vpp home
```

This will create an memif in the vpp and fork into the background. 

To connect to peers, just like original wireguard-go, use wireguard-tool but use custom userspace implantation

Remember to replace the path to real path
```
export WG_QUICK_USERSPACE_IMPLEMENTATION=$HOME/wireguard-go-vpp/wireguard-go-vpp
wg setconf home /etc/wireguard/home.conf
```
**Root permission is not required** but you need the read/write access at `/run/vpp/api/api.sock`, `/var/run/vpp-memif-wg` and `/etc/wggo-vpp`. Or you can change the path by environment variables.

`wg-quick` are not supported now.

It will automatically remove the interface while closing. To remove the interface manually, use this command in the vppcli (assume the uid is 3)
```
delete interface memif memif3/3
delete memif socket id 3
```
You may instead remove the control socket via `rm -f /var/run/wireguard/home.sock`, which will result in wireguard-go-vpp shutting down.

To run wireguard-go-vpp without forking to the background, pass `-f` or `--foreground`:

```
$ wireguard-go-vpp -f home
```

When an interface is running, you may use [`wg(8)`](https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8) to configure it.

To run with more logging you may set the environment variable `LOG_LEVEL=debug`.

## Make userspace apps join VPP network

Remember to replace the path to real path
```
export LDP_DEBUG=0
export VCL_DEBUG=0
export VCL_VPP_API_SOCKET="/run/vpp/api.sock"
export LD_PRELOAD="/usr/lib/x86_64-linux-gnu/libvcl_ldpreload.so"
```

## Platforms

Only linux are tested, other platform may work but I am not sure.


## Building

This requires an installation of [go](https://golang.org) ≥ 1.16.

```
$ git clone https://github.com/KusakabeSi/wireguard-go-vpp
$ cd wireguard-go-vpp
$ make
```

## License

    Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
    
    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
    of the Software, and to permit persons to whom the Software is furnished to do
    so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

