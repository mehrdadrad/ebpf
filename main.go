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

	ipList := []string{"0.0.0.0/0"}
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
				a := binary.LittleEndian.Uint64(value[0:8])
				b := binary.LittleEndian.Uint64(value[8:16])
				d := binary.LittleEndian.Uint64(value[16:24])
				fmt.Printf("%18s    %v  %v  tcp=%v %v\n", ipList[i], a, b, d, value)

				for i:=0; i < 200; i++ {
				vtcp, err := tcpmap.LookupInt(i)
				if err != nil {
					log.Fatal(err)
				}
				if vtcp > 0 {
				fmt.Printf("%v\n", vtcp)
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
