package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/dropbox/goebpf"
)

type Records struct {
	Packet  int64
	Counter int64
}

func main() {
	bpf := goebpf.NewDefaultEbpfSystem()
	err := bpf.LoadElf("xdp_mon.elf")
	if err != nil {
		log.Println(err)
	}

	subnets := bpf.GetMapByName("subnets")
	if subnets == nil {
		log.Println("eBPF map 'subnets' not found")
	}

	stats4 := bpf.GetMapByName("stats4")
	if stats4 == nil {
		log.Println("eBPF map 'stats4' not found")
	}

	tcpmap := bpf.GetMapByName("tcpmap")
	if tcpmap == nil {
		log.Println("eBPF map 'tcpmap' not found")
	}

	ipList := []string{"192.168.55.15/32"}
	for index, ip := range ipList {
		err = subnets.Insert(goebpf.CreateLPMtrieKey(ip), index)
		if err != nil {
			log.Fatal(err)
		}
	}

	xdp := bpf.GetProgramByName("monitor")
	if xdp == nil {
		log.Fatal("Program 'monitor' not found")
	}

	err = xdp.Load()
	if err != nil {
		log.Fatal(err)
	}

	err = xdp.Attach("enp0s3")
	if err != nil {
		log.Fatal("xdp.Attach(): enp0s3")
	}
	defer xdp.Detach()

	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)

	ticker := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-ticker.C:
			for i := 0; i < len(ipList); i++ {
				value, err := stats4.Lookup(i)
				if err != nil {
					log.Fatal("LookupInt failed: %v", err)
				}
				packets := binary.LittleEndian.Uint64(value[0:8])
				volume := binary.LittleEndian.Uint64(value[8:16])
				tcpCounter := binary.LittleEndian.Uint64(value[16:24])
				udpCounter := binary.LittleEndian.Uint64(value[24:32])
				icmpCounter := binary.LittleEndian.Uint64(value[32:40])
				fmt.Printf("%18s    %v  vol=%v  tcp=%v, udp=%v icmp=%v\n",
					ipList[i], packets, volume, tcpCounter, udpCounter, icmpCounter)

				for i := 0; i < 250; i++ {
					vtcp, err := tcpmap.LookupInt(i)
					if err != nil {
						log.Fatal(err)
					}
					if vtcp > 0 {
						fmt.Printf("%v %v\n", i, vtcp)
					}
				}
			}
		case <-ctrlC:
			fmt.Println("\nDetaching program and exit")
			return
		case <-time.After(30 * time.Second):
			return
		}
	}
}
