package main

import (
	"flag"
	"fmt"
	apns "github.com/kwillick/apns"
	"os"
	"time"
)

func main() {
	var caRootFile, certFile, keyFile string
	flags := flag.NewFlagSet("certificates", flag.ContinueOnError)
	flags.StringVar(&caRootFile, "carootfile", "", "Path to the root certifcate authority file")
	flags.StringVar(&certFile, "certfile", "", "Path to the certificate file")
	flags.StringVar(&keyFile, "keyfile", "", "Path to the key file")
	if err := flags.Parse(os.Args[1:]); err != nil {
		panic(err)
	}

	gateway := apns.Gateway{"localhost", "2195"}
	conn, err := apns.ConnectionWithRootCA(gateway, caRootFile, certFile, keyFile)
	if err != nil {
		panic(err)
	}

	errorChannel := make(chan *apns.PushNotificationError)
	err = conn.Connect(errorChannel)
	if err != nil {
		conn.Close()
		panic(err)
	}

	go func() {
		err := <-errorChannel
		fmt.Printf("%v\n", err)
		panic(err)
	}()

	fakeDeviceToken := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	for i := 0; i < 10; i++ {
		conn.SendBasicNotification(fakeDeviceToken, fmt.Sprintf("%v", i), "", i)
	}

	time.Sleep(time.Duration(5) * time.Second)
}
