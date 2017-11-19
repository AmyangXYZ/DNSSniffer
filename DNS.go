package main

// DNSRecord ...
type DNSRecord struct {
	ID         uint16 `json:"id"`
	Time       string `json:"time"`
	Type       uint16 `json:"type"`
	Name       string `json:"name"`
	RemoteAddr string `json:"raddr"`
}

// DNSMsg is specified in RFC 1034 / RFC 1035
// +---------------------+
// |        Header       |
// +---------------------+
// |       Question      | the question for the name server
// +---------------------+
// |        Answer       | RRs answering the question
// +---------------------+
// |      Authority      | RRs pointing toward an authority
// +---------------------+
// |      Additional     | RRs holding additional information
// +---------------------+
//
//  DNS Header
//  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                      ID                       |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    QDCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    ANCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    NSCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    ARCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
type DNSMsg struct {
	Header    dnsHeader
	Questions []dnsQuestion
	Answers   []dnsAnswer
}

type dnsHeader struct {
	ID                                 uint16
	Bits                               uint16
	Qdcount, Ancount, Nscount, Arcount uint16
}

type dnsQuestion struct {
	Name   string
	Qtype  uint16
	Qclass uint16
}

type dnsAnswer struct {
	Name   uint16
	Qtype  uint16
	Qclass uint16
	QLive  uint32
	QLen   uint16
	CName  string
}

func (header *dnsHeader) SetFlag(QR uint16, OperationCode uint16, AuthoritativeAnswer uint16, Truncation uint16, RecursionDesired uint16, RecursionAvailable uint16, ResponseCode uint16) {
	header.Bits = QR<<15 + OperationCode<<11 + AuthoritativeAnswer<<10 + Truncation<<9 + RecursionDesired<<8 + RecursionAvailable<<7 + ResponseCode
}
