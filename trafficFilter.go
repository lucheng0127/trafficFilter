package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/oschwald/maxminddb-golang"
	"golang.org/x/sys/unix"
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

		if record.Country.IsoCode != "CN" && record.Country.IsoCode != "PRIVATE" {
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
	l, err := attachProg(iface, ifaceIdx, objs.BpfProgPrograms.GeoipMark)
	if err != nil {
		log.Fatalf("attach tc bpf: %v", err)
	}

	fmt.Printf("[+] eBPF program attached to %s ingress\n", iface)

	// 5. 处理信号退出，清理
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)

	<-c
	fmt.Println("\n[+] Caught signal, cleaning up...")

	if l != nil {
		// 内核 >= 6.6
		l.Close()
	} else {
		// 内核 < 6.6
		pinPath := fmt.Sprintf("/sys/fs/bpf/%s_geoip_mark", iface)
		exec.Command("tc", "filter", "del", "dev", iface, "ingress").Run()
		exec.Command("tc", "qdisc", "del", "dev", iface, "clsact").Run()
		objs.BpfProgPrograms.GeoipMark.Unpin()
		_ = os.Remove(pinPath)
	}

	fmt.Println("[+] Cleanup done, exiting.")
}

func ifaceIndex(name string) int {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		log.Fatalf("get iface %s: %v", name, err)
	}
	return iface.Index
}

// checkKernelVersion 返回内核主次版本
func checkKernelVersion() (int, int, error) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return 0, 0, err
	}
	release := string(uts.Release[:])
	release = strings.Trim(release, "\x00")
	parts := strings.Split(release, ".")
	if len(parts) < 2 {
		return 0, 0, fmt.Errorf("unexpected uname release: %s", release)
	}
	major, _ := strconv.Atoi(parts[0])
	minor, _ := strconv.Atoi(parts[1])
	return major, minor, nil
}

// attachProg 根据内核版本选择 attach 方法：
//   - 内核 >= 6.6: 直接用 ebpf-go 的 AttachTCX
//   - 内核 < 6.6: 先 pin 程序到 bpffs，再用 tc filter pinned attach
//
// 返回 link.Link (仅在内核 >= 6.6 有效)，老内核时返回 nil
func attachProg(iface string, ifaceIdx int, prog *ebpf.Program) (link.Link, error) {
	major, minor, err := checkKernelVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to check kernel version: %w", err)
	}

	// --------- 新内核：直接用 TCX ---------
	if major > 6 || (major == 6 && minor >= 6) {
		log.Printf("Kernel %d.%d >= 6.6, using TCX attach", major, minor)
		l, err := link.AttachTCX(link.TCXOptions{
			Interface: ifaceIdx,
			Attach:    ebpf.AttachTCXIngress,
			Program:   prog,
		})
		if err != nil {
			return nil, fmt.Errorf("attach TCX failed: %w", err)
		}
		return l, nil
	}

	// --------- 老内核：pin + tc filter attach ---------
	log.Printf("Kernel %d.%d < 6.6, fallback to tc filter attach", major, minor)

	// 确保 /sys/fs/bpf 已挂载
	if out, err := exec.Command("mountpoint", "-q", "/sys/fs/bpf").CombinedOutput(); err != nil {
		if err := exec.Command("mount", "-t", "bpf", "bpf", "/sys/fs/bpf").Run(); err != nil {
			return nil, fmt.Errorf("failed to mount bpffs: %v, out: %s", err, out)
		}
	}

	// Pin program
	pinPath := fmt.Sprintf("/sys/fs/bpf/%s_geoip_mark", iface)
	_ = os.Remove(pinPath) // 删除旧 pin
	if err := prog.Pin(pinPath); err != nil {
		return nil, fmt.Errorf("failed to pin prog: %w", err)
	}

	// 确保 clsact 存在
	if err := exec.Command("tc", "qdisc", "add", "dev", iface, "clsact").Run(); err != nil {
		log.Printf("tc qdisc add maybe exists: %v", err)
	}

	// 挂载 pinned 程序
	// 注意: 不同 tc 版本可能是 "da pinned" 或 "direct-action pinned"
	cmd := exec.Command("tc", "filter", "replace", "dev", iface, "ingress",
		"bpf", "direct-action", "pinned", pinPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("tc filter add failed: %v, output: %s", err, out)
	}

	log.Printf("tc filter attached via pinned program: %s", pinPath)

	// 老内核没有 link.Link 对象，只能返回 nil
	return nil, nil
}
