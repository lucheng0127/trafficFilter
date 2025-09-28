package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/oschwald/maxminddb-golang"
)

// MaxMind 数据记录
type geoRecord struct {
	Country struct {
		IsoCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// LPM key (要和C结构体一致)
type lpmKeyV4 struct {
	PrefixLen uint32
	Addr      uint32
}

func main() {
	var mmdbPath, iface string
	var fwmark uint
	flag.StringVar(&mmdbPath, "db", "GeoLite2-Country.mmdb", "Path to MaxMind GeoIP database")
	flag.StringVar(&iface, "iface", "eth0", "Network interface to attach eBPF program")
	flag.UintVar(&fwmark, "fwmark", 1, "Fwmark to set for non-CN traffic")
	flag.Parse()

	// 1. 加载 eBPF 对象
	objs := BpfProgObjects{}
	if err := LoadBpfProgObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// 2. 写入 fwmark
	idx := uint32(0)
	val := uint32(fwmark)
	if err := objs.FwmarkConf.Update(&idx, &val, ebpf.UpdateAny); err != nil {
		log.Fatalf("failed to set fwmark: %v", err)
	}
	fmt.Printf("[+] fwmark set to %d\n", fwmark)

	// 3. 打开 MaxMind 数据库
	db, err := maxminddb.Open(mmdbPath)
	if err != nil {
		log.Fatalf("failed to open maxmind db: %v", err)
	}
	defer db.Close()

	// 遍历数据库
	networks := db.Networks(maxminddb.SkipAliasedNetworks)
	count := 0
	for networks.Next() {
		record := new(geoRecord)
		subnet, err := networks.Network(record)
		if err != nil {
			continue
		}

		if record.Country.IsoCode != "CN" {
			continue
		}

		if subnet.IP.To4() != nil {
			ones, _ := subnet.Mask.Size()
			ip := binary.BigEndian.Uint32(subnet.IP.To4())
			key := lpmKeyV4{PrefixLen: uint32(ones), Addr: ip}
			val := uint8(1)
			if err := objs.CnPrefixes.Update(&key, &val, ebpf.UpdateAny); err == nil {
				count++
			}
		}
	}
	fmt.Printf("[+] loaded %d CN prefixes into map\n", count)

	// 4. 挂载到指定网卡 ingress
	ifaceIdx := ifaceIndex(iface)
	l, err := link.AttachTCX(link.TCXOptions{
		Interface: ifaceIdx,
		Attach:    ebpf.AttachTCXIngress,
		Program:   objs.GeoipMark,
	})
	if err != nil {
		log.Fatalf("attach tc bpf: %v", err)
	}
	defer l.Close()

	fmt.Printf("[+] eBPF program attached to %s ingress\n", iface)

	select {}
}

func ifaceIndex(name string) int {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		log.Fatalf("get iface %s: %v", name, err)
	}
	return iface.Index
}
