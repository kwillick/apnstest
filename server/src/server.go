package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"time"
)

var PushResponses = map[uint8]string{
	0:   "No errors",
	1:   "Processing error",
	2:   "Missing device token",
	3:   "Missing topic",
	4:   "Missing payload",
	5:   "Invalid token size",
	6:   "Invalid topic size",
	7:   "Invalid payload size",
	8:   "Invalid token",
	10:  "Shutdown",
	255: "None (unknown)",
}

func readFileBytes(path string) ([]byte, error) {
	file, openErr := os.Open(path)
	if openErr != nil {
		return nil, openErr
	}
	defer file.Close()

	return ioutil.ReadAll(file)
}

func loadTLSConfig(caRootCertFile, caCertFile, caKeyFile string) (*tls.Config, error) {
	caRootCertBytes, caRootCertReadErr := readFileBytes(caRootCertFile)
	if caRootCertReadErr != nil {
		return nil, caRootCertReadErr
	}

	caCertBytes, caCertReadErr := readFileBytes(caCertFile)
	if caCertReadErr != nil {
		return nil, caCertReadErr
	}

	caKeyBytes, caKeyReadErr := readFileBytes(caKeyFile)
	if caKeyReadErr != nil {
		return nil, caKeyReadErr
	}

	cax509Cert, parseErr := x509.ParseCertificate(caRootCertBytes)
	if parseErr != nil {
		return nil, parseErr
	}

	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(cax509Cert)

	caTLSCert, pairErr := tls.X509KeyPair(caCertBytes, caKeyBytes)
	if pairErr != nil {
		return nil, pairErr
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{caTLSCert},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAnyClientCert,
	}

	return config, nil
}

type Command struct {
	Command uint8
	Length  uint32
	Items   []Item
}

func ParseCommandStart(reader io.Reader) (*Command, error) {
	command := &Command{}
	// 5 byte command start
	buf := make([]byte, 5)
	if _, err := reader.Read(buf); err != nil {
		return nil, err
	}
	command.Command = (uint8)(buf[0])

	bufReader := bytes.NewReader(buf[1:])
	if err := binary.Read(bufReader, binary.BigEndian, &command.Length); err != nil {
		return nil, err
	}

	return command, nil
}

func (c *Command) ParseItems(reader io.Reader) error {
	buf := make([]byte, c.Length)
	_, err := reader.Read(buf)
	if err != nil {
		return err
	}

	c.Items = make([]Item, 5)
	bufReader := bytes.NewReader(buf)
	for bufReader.Len() > 0 {
		item, err := parseItem(bufReader)
		if err != nil {
			return err
		}
		c.Items = append(c.Items, item)
	}

	return nil
}

func parseItem(reader io.Reader) (Item, error) {
	var item Item

	// Read the id
	if err := binary.Read(reader, binary.BigEndian, &item.Id); err != nil {
		return item, err
	}

	// Read the length
	if err := binary.Read(reader, binary.BigEndian, &item.Length); err != nil {
		return item, err
	}

	item.Data = make([]byte, item.Length)
	if _, err := reader.Read(item.Data); err != nil {
		return item, err
	}

	return item, nil
}

func (c *Command) String() string {
	output := fmt.Sprintf("Header: %v, Length: %v {\n", c.Command, c.Length)
	for i := range c.Items {
		output += c.Items[i].String()
	}
	output += "}\n"
	return output
}

type Item struct {
	Id     uint8
	Length uint16
	Data   []byte
}

func (item *Item) String() string {
	switch item.Id {
	case 1:
		hexToken := hex.EncodeToString(item.Data)
		return fmt.Sprintf("Device Token: <%v>,\n", hexToken)
	case 2:
		return fmt.Sprintf("Payload: '%s',\n", (string)(item.Data))
	case 3:
		reader := bytes.NewReader(item.Data)
		var identifier uint32
		if err := binary.Read(reader, binary.BigEndian, &identifier); err != nil {
			panic(err)
		}
		return fmt.Sprintf("Identifier: '%v',\n", identifier)
	case 4:
		reader := bytes.NewReader(item.Data)
		var expiration uint32
		if err := binary.Read(reader, binary.BigEndian, &expiration); err != nil {
			panic(err)
		}
		t := time.Unix((int64)(expiration), 0)
		return fmt.Sprintf("Expiration: '%v',\n", t)
	case 5:
		priority := (int)(item.Data[0])
		return fmt.Sprintf("Priority: '%v',\n", priority)
	}

	return ""
}

type ErrorResponse struct {
	Status     uint8
	Identifier uint32
}

func (e *ErrorResponse) ToBytes() []byte {
	buffer := new(bytes.Buffer)
	buffer.WriteByte(8)
	buffer.WriteByte(e.Status)
	binary.Write(buffer, binary.BigEndian, e.Identifier)
	return buffer.Bytes()
}

func (e *ErrorResponse) Error() string {
	return PushResponses[e.Status]
}

func RunEchoServer(caRootFile, certFile, keyFile string) {
	tlsConfig, tlsConfigErr := loadTLSConfig(caRootFile, certFile, keyFile)
	if tlsConfigErr != nil {
		panic(tlsConfigErr)
	}

	listener, listenErr := tls.Listen("tcp", ":2195", tlsConfig)
	if listenErr != nil {
		panic(listenErr)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Conn errored: %s", err)
			conn.Close()
		}
		fmt.Printf("Connection to: %+v\n", conn.RemoteAddr())

		for {
			command, err := ParseCommandStart(conn)
			if err != nil {
				if err == io.EOF {
					fmt.Printf("Connection closed\n")

				} else {
					fmt.Printf("error: %s\n", err)
				}
				conn.Close()
				break
			}

			if err := command.ParseItems(conn); err != nil {
				fmt.Printf("error: %s\n", err)
				conn.Close()
				break
			}

			fmt.Printf("%v\n", command)
		}
	}
}

func main() {
	var caRootFile, certFile, keyFile string
	flags := flag.NewFlagSet("certificates", flag.ContinueOnError)
	flags.StringVar(&caRootFile, "carootfile", "", "Path to the root certifcate authority file")
	flags.StringVar(&certFile, "certfile", "", "Path to the certificate file")
	flags.StringVar(&keyFile, "keyfile", "", "Path to the key file")
	if err := flags.Parse(os.Args[1:]); err != nil {
		panic(err)
	}

	RunEchoServer(caRootFile, certFile, keyFile)
}
