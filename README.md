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

You have to setup vpp first. Start VPP and run following command in vppcli

if you want to run it in pure userspace, remember to set dpdk config to `"no-pci no-hugetlb"`

Remember to replace the IP Range/MacAddr/BridgeID/InstanceID to what you want

In this case, InstanceID=42 / BridgeID=4242 / MacAddr=42:42:42:42:42:42
```
loop create mac 42:42:42:42:42:42 instance 42
set int l2 bridge loop42 4242 bvi
set interface mtu 1500 loop42
set int state loop42 up

set interface ip address loop42 192.168.37.1/24
set interface ip address loop42 fd42:4242:4242::1/10
```

Similar to original wireguard-go, but you have to configure some config for the memif.

Create a json file in `/etc/wggo-vpp/wg0.json` with following content:

```
{
    "uid": 3,
    "secret": "pwd",
    "GatewayMacAddr": "42:42:42:42:42:42",
    "IPv4ArpResponseRanges": [ "192.168.37.128/30" ],
    "IPv4ArpLearningRanges": [ "192.168.37.0/24" ],
    "IPv6NdpNeighAdvRanges": [ "fd42::/64" ],
    "IPv6NdpLearningRanges": [ "fd42::/64" ],
    "VppBridgeID": 4242
}

```

### parameters
1. uid: Unique ID for vpp interface id, must be unique in the vpp runtime.
2. secret: the secret for the connection between vpp and wggo-vpp
3. IPv4ArpResponseRanges: While DstIP in this range, it will reply the ARP if an ARP request packet received.
4. IPv6NdpNeighAdvRanges: Similar to `IPv4ArpResponseRanges`, but it replies Neighbor Advertisement if a Neighbor Solicitation received.
5. GatewayMacAddr: The mac address of the gateway. If the dstIP out of the learning range defined below, it will use this Mac address as DstMacAddr in the vpp side.
6. IPv4ArpLearningRanges(Optional): Any dstIP within this range, wggo-vpp will lookup it's the MacAddr in the ARP table to fill the layer 2 part. If the lookup failed, it will send an ARP request and drop the original packet.
7. IPv6NdpLearningRanges(Optional): Same as `IPv4ArpLearningRanges`, but IPv6 version

While the JSON configured, you can run wireguard-go-vpp via following command:

```
$ wireguard-go wg0
```

This will create an memif in the vpp and fork into the background. 

To connect to peers, just like original wireguard-go, use wireguard-tool but use custom userspace implantation

Remember to replace the path to real path
```
export WG_QUICK_USERSPACE_IMPLEMENTATION=$HOME/wireguard-go-vpp/wireguard-go
wg setconf wg0 /etc/wireguard/wg0.conf
```
Root permission is not required but you need the read/write access at `/run/vpp/api/api.sock`, `/var/run/vpp-memif-wg` and `/etc/wggo-vpp`. Or you can change the path by environment variables.

`wg-quick` are not supported now.

It will automatically remove the interface while closing. To remove the interface manually, use this command in the vppcli (assume the uid is 3)
```
delete interface memif memif3/3
delete memif socket id 3
```
You may instead remove the control socket via `rm -f /var/run/wireguard/wg0.sock`, which will result in wireguard-go shutting down.

To run wireguard-go without forking to the background, pass `-f` or `--foreground`:

```
$ wireguard-go -f wg0
```

When an interface is running, you may use [`wg(8)`](https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8) to configure it.

To run with more logging you may set the environment variable `LOG_LEVEL=debug`.

## Make userspace apps join VPP network

Remember to replace the path to real path
```
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

