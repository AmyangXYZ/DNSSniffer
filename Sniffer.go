package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// RunSniffer ...
func RunSniffer() {
	udpAddr, err := net.ResolveUDPAddr("udp4", ":53")
	checkError(err)

	fmt.Printf("Listening on %s ...\n", udpAddr)
	var s Sniffer
	s.buf = make([]byte, 512)

	s.conn, err = net.ListenUDP("udp4", udpAddr)
	checkError(err)

	defer s.conn.Close()
	for {
		s.Handle()
	}
}

// Sniffer ...
type Sniffer struct {
	buf  []byte
	conn *net.UDPConn
}

// Handle DNSMsg
func (s *Sniffer) Handle() {

	n, raddr, err := s.conn.ReadFromUDP(s.buf[0:])
	checkError(err)

	var msg DNSMsg

	msg.UnPack(s.buf[0:n])

	record := DNSRecord{
		ID:         msg.Header.ID,
		Time:       time.Now().Format("2006-01-02 15:04:05"),
		Type:       msg.Questions[0].Qtype,
		Name:       msg.Questions[0].Name,
		RemoteAddr: raddr.String(),
	}

	recordjson, err := json.Marshal(record)
	checkError(err)

	fmt.Println(string(recordjson))

	answer := msg.Pack()
	s.conn.WriteToUDP(answer, raddr)

}

// Pack Answer Packet
func (msg *DNSMsg) Pack() []byte {
	var buffer bytes.Buffer

	msg.Answers = make([]dnsAnswer, 1)

	msg.Header.Ancount = 1
	msg.Header.Arcount = 0

	msg.Header.SetFlag(1, 0, 0, 0, 1, 1, 0)

	msg.Answers[0] = dnsAnswer{
		Name:   49164, // 0xc00c
		Qtype:  1,
		Qclass: 1,
		QLive:  360,
		QLen:   4,
	}

	// dnsHeader
	binary.Write(&buffer, binary.BigEndian, msg.Header)

	// dnsQuestion
	msg.Questions[0].Qtype = 1
	for _, seg := range strings.Split(msg.Questions[0].Name, ".") {
		binary.Write(&buffer, binary.BigEndian, byte(len(seg)))
		binary.Write(&buffer, binary.BigEndian, []byte(seg))
	}
	binary.Write(&buffer, binary.BigEndian, byte(0x00))

	binary.Write(&buffer, binary.BigEndian, msg.Questions[0].Qtype)
	binary.Write(&buffer, binary.BigEndian, msg.Questions[0].Qclass)

	// dnsAnswer
	binary.Write(&buffer, binary.BigEndian, msg.Answers[0].Name)
	binary.Write(&buffer, binary.BigEndian, msg.Answers[0].Qtype)
	binary.Write(&buffer, binary.BigEndian, msg.Answers[0].Qclass)
	binary.Write(&buffer, binary.BigEndian, msg.Answers[0].QLive)
	binary.Write(&buffer, binary.BigEndian, msg.Answers[0].QLen)

	ip := "123.206.63.201"

	for _, seg := range strings.Split(ip, ".") {
		i, _ := strconv.Atoi(seg)
		binary.Write(&buffer, binary.BigEndian, byte(i))
	}

	return buffer.Bytes()
}

// UnPack Question Packet
func (msg *DNSMsg) UnPack(buf []byte) *DNSMsg {
	msg.Header = dnsHeader{
		ID:      binary.BigEndian.Uint16(buf[0:2]),
		Bits:    binary.BigEndian.Uint16(buf[2:4]),
		Qdcount: binary.BigEndian.Uint16(buf[4:6]),
		Ancount: binary.BigEndian.Uint16(buf[6:8]),
		Nscount: binary.BigEndian.Uint16(buf[8:10]),
		Arcount: binary.BigEndian.Uint16(buf[10:12]),
	}

	msg.Questions = make([]dnsQuestion, int(msg.Header.Qdcount))
	msg.Answers = make([]dnsAnswer, int(msg.Header.Ancount))

	i := 12
	for j := 0; j < int(msg.Header.Qdcount); j++ {
		k := int(buf[i])
		question := dnsQuestion{}
		for ; k != 0; k = int(buf[i]) {
			question.Name += string(buf[i+1:i+k+1]) + "."
			i += k + 1
		}
		i++
		question.Name = strings.TrimRight(question.Name, ".")
		question.Qtype = binary.BigEndian.Uint16(buf[i : i+2])
		question.Qclass = binary.BigEndian.Uint16(buf[i+2 : i+4])

		msg.Questions[j] = question
	}
	fmt.Println(msg.Questions[0].Qtype)

	return msg
}

func checkError(err error) {
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		os.Exit(1)
	}
}
