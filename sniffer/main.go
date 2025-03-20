//go:build linux

package main

import (
	"bufio"
	"bytes"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	_ "github.com/lib/pq"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
	"gopkg.in/natefinch/lumberjack.v2"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go  -cc clang -target amd64 -type emit_event bpf ./c/tcptracer.c -- -I../headers -I./c

var fname = flag.String("r", "eth0", "Filename to read from")

func main() {
	flag.Parse()
	ConfigLoger()
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		logrus.Errorf("error setting rlimit: %v", err)
		return
	}

	// Find the path to a cgroup enabled to version 2
	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		logrus.Errorf("loading objects: %v", err)
		return
	}
	defer objs.Close()

	cgroupPath, err := detectCgroupPath()
	if err != nil {
		logrus.Errorf("error detecting cgroup path: %v", err)
	}

	// Link the count_egress_packets program to the cgroup.
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: objs.IgTraceSni,
	})
	if err != nil {
		logrus.Errorf("error attaching to cgroup: %v", err)
		return
	}
	defer l.Close()

	listen_start, err := link.Kprobe("inet_listen", objs.bpfPrograms.InetListenEntry, nil)
	if err != nil {
		logrus.Errorf("error attach listen_start: %v", err)
		return
	}
	defer listen_start.Close()

	listen_stop, err := link.Kprobe("inet_csk_listen_stop", objs.bpfPrograms.InetCskListenStop, nil)
	if err != nil {
		logrus.Errorf("error attach listen_stop: %v", err)
		return
	}
	defer listen_stop.Close()
	inet_bind, err := link.Kprobe("inet_bind", objs.bpfPrograms.BindIpv4Entry, nil)
	if err != nil {
		logrus.Errorf("error attach inet_bind: %v", err)
		return
	}
	defer inet_bind.Close()

	inet6_bind, err := link.Kprobe("inet6_bind", objs.bpfPrograms.BindIpv6Entry, nil)
	if err != nil {
		logrus.Errorf("error attach inet6_bind: %v", err)
		return
	}
	defer inet6_bind.Close()

	exit_inet_bind, err := link.Kretprobe("inet_bind", objs.bpfPrograms.BindIpv4Exit, nil)
	if err != nil {
		logrus.Errorf("error attach exit_inet_bind: %v", err)
		return
	}
	defer exit_inet_bind.Close()

	exit_inet6_bind, err := link.Kretprobe("inet6_bind", objs.bpfPrograms.BindIpv6Exit, nil)
	if err != nil {
		logrus.Errorf("error attach exit_inet6_bind: %v", err)
		return
	}
	defer exit_inet6_bind.Close()

	tcp_v4_connect, err := link.Kprobe("tcp_v4_connect", objs.bpfPrograms.TcpV4Connect, nil)
	if err != nil {
		logrus.Errorf("error attach tcp_v4_connect: %v", err)
		return
	}
	defer tcp_v4_connect.Close()

	tcp_v6_connect, err := link.Kprobe("tcp_v6_connect", objs.bpfPrograms.TcpV6Connect, nil)
	if err != nil {
		logrus.Errorf("error attach tcp_v6_connect: %v", err)
		return
	}
	defer tcp_v6_connect.Close()

	ret_tcp_v4_connect, err := link.Kretprobe("tcp_v4_connect", objs.bpfPrograms.TcpV4ConnectRet, nil)
	if err != nil {
		logrus.Errorf("error attach ret_tcp_v4_connect: %v", err)
		return
	}
	defer ret_tcp_v4_connect.Close()

	ret_tcp_v6_connect, err := link.Kretprobe("tcp_v6_connect", objs.bpfPrograms.TcpV6ConnectRet, nil)
	if err != nil {
		logrus.Errorf("error attach ret_tcp_v6_connect: %v", err)
		return
	}
	defer ret_tcp_v6_connect.Close()

	inet_csk_accept, err := link.Kretprobe("inet_csk_accept", objs.bpfPrograms.ExitInetCskAccept, nil)
	if err != nil {
		logrus.Errorf("error attach exit_inet_csk_accept: %v", err)
		return
	}
	defer inet_csk_accept.Close()
	inet_sock_set_state, err := link.Tracepoint("sock", "inet_sock_set_state", objs.bpfPrograms.HandleSetState, nil)
	if err != nil {
		logrus.Errorf("failed to attach the BPF program to inet_sock_set_state tracepoint: %v", err)
		return
	}
	defer inet_sock_set_state.Close()

	db, err := sql.Open("postgres", "host=172.20.44.101 port=5432 user=dbuser_dba password=DBUser.DBA dbname=postgres sslmode=disable")
	if err != nil {
		logrus.Errorf("failed to open db: %v", err)
	}
	defer db.Close()
	err = createTableIfNotExists(db)
	if err != nil {
		logrus.Errorf("failed to create table: %v", err)
		return
	}

	rd, err := ringbuf.NewReader(objs.bpfMaps.Events)
	if err != nil {
		logrus.Errorf("opening ringbuf reader: %s", err)
		return
	}
	defer rd.Close()
	go readLoop(rd, db)
	pcapFile := *fname
	if len(pcapFile) != 0 {
		if _, err := os.Stat(pcapFile); os.IsNotExist(err) {
			handle, err := pcap.OpenLive(pcapFile, 65536, true, pcap.BlockForever)
			if err != nil {
				logrus.Errorf("PCAP OpenLive error %s", err.Error())
				return
			}
			go handlePcap(handle, db, stopper)
		} else {
			handle, err := pcap.OpenOffline(pcapFile)
			if err != nil {
				logrus.Errorf("PCAP OpenOffline error %s", err.Error())
			}
			go handlePcap(handle, db, stopper)
		}
	}
	// Wait
	<-stopper
	logrus.Info("stop")
	time.Sleep(100 * time.Millisecond)
}

func handlePacket(packet gopacket.Packet, db *sql.DB) {
	var saddr string
	var daddr string
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4Layer != nil {
		if ipv4, ok := ipv4Layer.(*layers.IPv4); ok {
			saddr = ipv4.SrcIP.String()
			daddr = ipv4.DstIP.String()
		}
	}
	ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ipv6Layer != nil {
		if ipv6, ok := ipv6Layer.(*layers.IPv6); ok {
			saddr = ipv6.SrcIP.String()
			daddr = ipv6.DstIP.String()
		}
	}
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}

	if udp, ok := udpLayer.(*layers.UDP); ok {
		sport := uint16(udp.SrcPort)
		dport := uint16(udp.DstPort)
		parseDnsBytes(hex.EncodeToString(udp.Payload), saddr, daddr, sport, dport, db)
	}

}
func handlePcap(handle *pcap.Handle, db *sql.DB, stopper <-chan os.Signal) {
	handle.SetBPFFilter("udp and port 53")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	defer handle.Close()
	for {
		select {
		case packet := <-packets:
			if packet == nil {
				return
			}
			handlePacket(packet, db)
		case <-stopper:
			return
		}
	}

}

type dnsEvent struct {
	op        string
	id        uint16
	cname     string
	saddr     string
	daddr     string
	sport     uint16
	dport     uint16
	ips       string
	queryType string
	queryName string
}

func parseDnsBytes(dnsQueryStr string, saddr, daddr string, sport, dport uint16, db *sql.DB) {

	dnsQueryBytes, err := hex.DecodeString(dnsQueryStr)
	if err != nil {
		logrus.Errorf("Error decoding hex string:", err)
		return
	}
	var m dnsmessage.Message
	err = m.Unpack(dnsQueryBytes)
	if err != nil {
		logrus.Errorf("Error unpacking dns message:", err)
		return
	}
	var queryName string
	var queryType string
	fmt.Print(m.ID)
	for _, q := range m.Questions {
		queryName = q.Name.String()
		queryType = q.Type.String()
	}
	var answerIPs []net.IP
	var cnameStr string
	for _, a := range m.Answers {
		switch t := a.Body.(type) {
		case *dnsmessage.AResource:
			answerIPs = append(
				answerIPs,
				t.A[:],
			)

		case *dnsmessage.CNAMEResource:
			cnameStr = t.CNAME.String()

		case *dnsmessage.AAAAResource:
			answerIPs = append(
				answerIPs,
				t.AAAA[:],
			)
		default:
			continue
		}

	}
	opType := "query"
	var buffer bytes.Buffer
	buffer.WriteString(fmt.Sprintf("0x%x ", m.ID))
	if len(m.Answers) != 0 || len(m.Authorities) != 0 || len(m.Additionals) != 0 {
		opType = "answer"
		buffer.WriteString(fmt.Sprintf("dns answer %s %s", queryName, queryType))
	} else {
		buffer.WriteString(fmt.Sprintf("dns query %s %s", queryName, queryType))
	}
	if len(cnameStr) > 0 {
		buffer.WriteString(fmt.Sprintf(" cname %s", cnameStr))
	}
	ips := make([]string, 0)
	for _, ip := range answerIPs {
		ips = append(ips, ip.String())
	}
	ipListStr := strings.Join(ips, ",")
	dnsEvent := dnsEvent{}
	dnsEvent.op = opType
	dnsEvent.id = m.ID
	dnsEvent.cname = cnameStr
	dnsEvent.saddr = saddr
	dnsEvent.daddr = daddr
	dnsEvent.sport = sport
	dnsEvent.dport = dport
	dnsEvent.ips = ipListStr
	dnsEvent.queryType = queryType
	dnsEvent.queryName = queryName
	if len(ips) != 0 {
		buffer.WriteString(" ")
		buffer.WriteString(ipListStr)
	}
	// isnert into db dns event
	querySql := `INSERT INTO dns_event (op, event_id, cname, saddr, daddr, sport, dport, query_type, query_name) VALUES ($1, $2, $3, $4, $5, $6, $7, $8,$9)`
	answerSql := `INSERT INTO dns_event (op, event_id, cname, saddr, daddr, sport, dport, query_type, query_name, ips) VALUES ($1, $2, $3, $4, $5, $6, $7, $8,$9,$10)`
	if dnsEvent.op == "query" {
		_, err = db.Exec(querySql, dnsEvent.op, dnsEvent.id, dnsEvent.cname, dnsEvent.saddr, dnsEvent.daddr, dnsEvent.sport, dnsEvent.dport, dnsEvent.queryType, dnsEvent.queryName)
		if err != nil {
			logrus.Errorf("inserting query dns event failed %s", err)
			return
		}
	}
	if dnsEvent.op == "answer" {
		_, err = db.Exec(answerSql, dnsEvent.op, dnsEvent.id, dnsEvent.cname, dnsEvent.saddr, dnsEvent.daddr, dnsEvent.sport, dnsEvent.dport, dnsEvent.queryType, dnsEvent.queryName, dnsEvent.ips)
		if err != nil {
			logrus.Errorf("inserting answer dns event failed %s", err)
			return
		}
	}
	logrus.Info(buffer.String())
}
func detectCgroupPath() (string, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// example fields: cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return fields[1], nil
		}
	}

	return "", errors.New("cgroup2 not mounted")
}

func createTableIfNotExists(db *sql.DB) error {
	createEventTableSQL := `
        CREATE TABLE IF NOT EXISTS bpf_emit_event (
            id SERIAL PRIMARY KEY,
            saddr TEXT,
            daddr TEXT,
            type BIGINT,
            oldstate TEXT,
            newstate TEXT,
            task TEXT,
            ts_us BIGINT,
            delta_us BIGINT,
            af INTEGER,
            pid INTEGER,
            uid INTEGER,
            protocol TEXT,
            sport BIGINT,
            dport BIGINT,
            rxb BIGINT,
            txb BIGINT,
            bytes_retrans BIGINT,
            total_retrans INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `
	createDnsTableSQL := `
        CREATE TABLE IF NOT EXISTS dns_event (
            id SERIAL PRIMARY KEY,
	        event_id BIGINT,
			op TEXT,
            saddr TEXT,
            daddr TEXT,
            query_type TEXT,
            query_name TEXT,
            cname TEXT,
            ips TEXT,
            sport BIGINT,
            dport BIGINT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `

	_, err := db.Exec(createEventTableSQL)
	if err != nil {
		logrus.Errorf("failed to create event table: %v", err)
	} else {
		logrus.Info("event table created or already exists")
	}
	_, err = db.Exec(createDnsTableSQL)
	if err != nil {
		logrus.Errorf("failed to create dns table: %v", err)
	} else {
		logrus.Info("dns table created or already exists")
	}
	return err
}

func readLoop(rd *ringbuf.Reader, db *sql.DB) {

	var event bpfEmitEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				logrus.Error("received signal, exiting..")
				return
			}
			logrus.Errorf("reading from reader: %s", err)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.NativeEndian, &event); err != nil {
			logrus.Errorf("parsing ringbuf event: %s", err)
			continue
		}

		af := 6
		if event.Af == 2 {
			af = 4
		}
		srcAddr := intToIP(event.SaddrV4)
		dstAddr := intToIP(event.DaddrV4)
		if af == 6 {
			srcAddr = AddrToIP(event.SaddrV6)
			dstAddr = AddrToIP(event.DaddrV6)
		}

		exeName := unix.ByteSliceToString(event.Task[:])
		if exeName == "frpc" || exeName == "sshd" {
			continue
		}
		if event.Type == 1 || event.Type == 2 {
			logrus.Infof("pid %-8d name %-16s type %-2d %-16s -> %-16s %-5d -> %-5d %s",
				event.Pid,
				unix.ByteSliceToString(event.Task[:]),
				af,
				srcAddr,
				dstAddr,
				event.Sport,
				event.Dport,
				typeToString(event.Type),
			)
			query := `INSERT INTO bpf_emit_event(pid,task,af,saddr,daddr,sport,dport,type) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`
			_, err := db.Exec(query, event.Pid, unix.ByteSliceToString(event.Task[:]), af, srcAddr, dstAddr, event.Sport, event.Dport, event.Type)
			if err != nil {
				logrus.Errorf("failed to insert data: %v", err)
			}
		} else if event.Type == 3 {
			if event.Newstate == 7 {
				logrus.Infof("pid %-8d name %-16s type %-2d %-16s -> %-16s %-5d -> %-5d %-12s -> %-12s life %.3f      RX %d TX %d REC %d RET %d",
					event.Pid,
					unix.ByteSliceToString(event.Task[:]),
					af,
					srcAddr,
					dstAddr,
					event.Sport,
					event.Dport,
					statusToString(event.Oldstate),
					statusToString(event.Newstate),
					float64(event.DeltaUs)/1000,
					event.RxB,
					event.TxB,
					event.TotalRetrans,
					event.BytesRetrans,
				)
				query := `INSERT INTO bpf_emit_event(pid,task,af,saddr,daddr,sport,dport,oldstate,newstate,delta_us,rxb,txb,bytes_retrans,total_retrans) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`
				_, err := db.Exec(query,
					event.Pid,
					unix.ByteSliceToString(event.Task[:]),
					af,
					srcAddr,
					dstAddr,
					event.Sport,
					event.Dport,
					statusToString(event.Oldstate),
					statusToString(event.Newstate),
					event.DeltaUs,
					event.RxB,
					event.TxB,
					event.TotalRetrans,
					event.BytesRetrans,
				)
				if err != nil {
					logrus.Errorf("failed to insert data: %v", err)
				}
			} else {
				logrus.Infof("pid %-8d name %-16s type %-2d %-16s -> %-16s %-5d -> %-5d %-12s -> %-12s life %.3f",
					event.Pid,
					unix.ByteSliceToString(event.Task[:]),
					af,
					srcAddr,
					dstAddr,
					event.Sport,
					event.Dport,
					statusToString(event.Oldstate),
					statusToString(event.Newstate),
					float64(event.DeltaUs)/1000)
				query := `INSERT INTO bpf_emit_event(pid,task,af,saddr,daddr,sport,dport,oldstate,newstate,delta_us) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`
				_, err := db.Exec(query,
					event.Pid,
					unix.ByteSliceToString(event.Task[:]),
					af,
					srcAddr,
					dstAddr,
					event.Sport,
					event.Dport,
					statusToString(event.Oldstate),
					statusToString(event.Newstate),
					event.DeltaUs,
				)
				if err != nil {
					logrus.Errorf("failed to insert data: %v", err)
				}
			}

		} else if event.Type == 4 {
			logrus.Infof("pid %-8d name %-16s type %-2d %-16s %-5d %s:%s",
				event.Pid,
				unix.ByteSliceToString(event.Task[:]),
				af,
				srcAddr,
				event.Sport,
				typeToString(event.Type),
				protocolToString(event.Protocol))
			query := `INSERT INTO bpf_emit_event(pid,task,af,saddr,daddr,sport,dport,type,protocol) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`
			_, err := db.Exec(query, event.Pid, unix.ByteSliceToString(event.Task[:]), af, srcAddr, dstAddr, event.Sport, event.Dport, event.Type, event.Protocol)
			if err != nil {
				logrus.Errorf("failed to insert data: %v", err)
			}
		} else if event.Type == 5 || event.Type == 6 {
			logrus.Infof("pid %-8d name %-16s type %-2d %-16s %-5d %s life %.3f",
				event.Pid,
				unix.ByteSliceToString(event.Task[:]),
				af,
				srcAddr,
				event.Sport,
				typeToString(event.Type),
				float64(event.DeltaUs)/1000)
			query := `INSERT INTO bpf_emit_event(pid,task,af,saddr,daddr,sport,dport,type,delta_us) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`
			_, err := db.Exec(query, event.Pid, unix.ByteSliceToString(event.Task[:]), af, srcAddr, dstAddr, event.Sport, event.Dport, event.Type, event.DeltaUs)
			if err != nil {
				logrus.Errorf("failed to insert data: %v", err)
			}
		} else if event.Type == 7 {
			logrus.Infof("SNI %s", unix.ByteSliceToString(event.Sni[:]))
		}
	}
}

func typeToString(t uint8) string {
	if t == 1 {
		return "CONNECT"
	}
	if t == 2 {
		return "ACCEPT"
	}
	if t == 3 {
		return "STATE_CHANGE"
	}
	if t == 4 {
		return "BIND"
	}
	if t == 5 {
		return "LISTEN_STOP"
	}
	if t == 6 {
		return "LISTEN_START"
	}
	if t == 7 {
		return "SNI"
	}

	return "UNKNOWN"
}
func statusToString(status uint8) string {
	tcpStates := []string{
		"",             // [0] 空值，未使用
		"ESTABLISHED",  // [1]
		"SYN_SENT",     // [2]
		"SYN_RECV",     // [3]
		"FIN_WAIT1",    // [4]
		"FIN_WAIT2",    // [5]
		"TIME_WAIT",    // [6]
		"CLOSE",        // [7]
		"CLOSE_WAIT",   // [8]
		"LAST_ACK",     // [9]
		"LISTEN",       // [10]
		"CLOSING",      // [11]
		"NEW_SYN_RECV", // [12]
		"UNKNOWN",      // [13]
	}
	return tcpStates[status]
}

// protocolToString translates a kernel protocol enum value to the protocol
// name.
func protocolToString(protocol uint16) string {
	var socketProtocol = map[uint16]string{
		0:   "IP",       // Dummy protocol for TCP
		1:   "ICMP",     // Internet Control Message Protocol
		2:   "IGMP",     // Internet Group Management Protocol
		4:   "IPIP",     // IPIP tunnels (older KA9Q tunnels use 94)
		6:   "TCP",      // Transmission Control Protocol
		8:   "EGP",      // Exterior Gateway Protocol
		12:  "PUP",      // PUP protocol
		17:  "UDP",      // User Datagram Protocol
		22:  "IDP",      // XNS IDP protocol
		29:  "TP",       // SO Transport Protocol Class 4
		33:  "DCCP",     // Datagram Congestion Control Protocol
		41:  "IPV6",     // IPv6-in-IPv4 tunnelling
		46:  "RSVP",     // RSVP Protocol
		47:  "GRE",      // Cisco GRE tunnels (rfc 1701,1702)
		50:  "ESP",      // Encapsulation Security Payload protocol
		51:  "AH",       // Authentication Header protocol
		92:  "MTP",      // Multicast Transport Protocol
		94:  "BEETPH",   // IP option pseudo header for BEET
		98:  "ENCAP",    // Encapsulation Header
		103: "PIM",      // Protocol Independent Multicast
		108: "COMP",     // Compression Header Protocol
		132: "SCTP",     // Stream Control Transport Protocol
		136: "UDPLITE",  // UDP-Lite (RFC 3828)
		137: "MPLS",     // MPLS in IP (RFC 4023)
		143: "ETHERNET", // Ethernet-within-IPv6 Encapsulation
		255: "RAW",      // Raw IP packets
		262: "MPTCP",    // Multipath TCP connection
	}

	protocolString, ok := socketProtocol[protocol]
	if !ok {
		protocolString = "UNKNOWN"
	}

	return protocolString
}

func AddrToIP(arr [16]uint8) string {
	return netip.AddrFrom16(arr).String()
}
func intToIP(ipNum uint32) string {
	ip := make(net.IP, 4)
	binary.NativeEndian.PutUint32(ip, ipNum)
	return ip.String()
}

type MyFormatter struct{}

func (m *MyFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	var b *bytes.Buffer
	if entry.Buffer != nil {
		b = entry.Buffer
	} else {
		b = &bytes.Buffer{}
	}

	timestamp := entry.Time.Format("20060102 15:04:05.999999")
	if entry.HasCaller() {
		fName := filepath.Base(entry.Caller.File)
		fmt.Fprintf(b, "%-24s %s %s %s:%d \n", timestamp, entry.Level, entry.Message, fName, entry.Caller.Line)
	} else {
		fmt.Fprintf(b, "%-24s %s %s\n", timestamp, entry.Level, entry.Message)
	}

	return b.Bytes(), nil
}
func ConfigLoger() {
	logger := &lumberjack.Logger{
		// 日志输出文件路径
		Filename: "tcptracer.log",
		// 日志文件最大 size, 单位是 MB
		MaxSize: 10, // megabytes
		// 最大过期日志保留的个数
		MaxBackups: 5,
		// 保留过期文件的最大时间间隔,单位是天
		MaxAge: 28, // days
	}

	writers := []io.Writer{os.Stdout, logger}

	fileAndStdoutWriter := io.MultiWriter(writers...)

	logrus.SetOutput(fileAndStdoutWriter)
	logrus.SetReportCaller(true)
	logrus.SetFormatter(&MyFormatter{})
	logrus.SetLevel(logrus.DebugLevel)
}
