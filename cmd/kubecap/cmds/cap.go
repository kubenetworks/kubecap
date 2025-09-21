package cmds

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/i18n"
	"k8s.io/kubectl/pkg/util/templates"
)

var (
	snapshot_len int32 = 1024
	promiscuous  bool  = false
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
	// Will reuse these for each packet
	ethLayer layers.Ethernet
	ipLayer  layers.IPv4
	ip6Layer layers.IPv6
	tcpLayer layers.TCP
	udpLayer layers.UDP
	icmp     layers.ICMPv4
	icmp6    layers.ICMPv6
	tls      layers.TLS
	dns      layers.DNS
	payload  gopacket.Payload
)

func NewCommand() *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "kubecap",
		Short: i18n.T("kubecap"),
		Long: templates.LongDesc(`
        kubecap capture pod network traffic
        `),
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cap(args[0])
		},
	}
	return cmd
}

func cap(device string) {
	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		parser := gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet,
			&ethLayer,
			&ipLayer,
			&tcpLayer,
			&udpLayer,
			&icmp,
			&icmp6,
			&payload,
			&tls,
			&ip6Layer,
			&dns,
		)
		foundLayerTypes := []gopacket.LayerType{}
		err := parser.DecodeLayers(packet.Data(), &foundLayerTypes)
		if err != nil {
			fmt.Println("Trouble decoding layers: ", err)
		}
		for _, layerType := range foundLayerTypes {
			if layerType == layers.LayerTypeIPv4 {
				fmt.Println("IPv4: ", ipLayer.SrcIP, "->", ipLayer.DstIP)
			}
			if layerType == layers.LayerTypeTCP {
				fmt.Println("TCP Port: ", tcpLayer.SrcPort, "->", tcpLayer.DstPort)
				fmt.Println("TCP SYN:", tcpLayer.SYN, " | ACK:", tcpLayer.ACK)
			}
		}
	}
}
