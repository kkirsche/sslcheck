// Copyright © 2016 Kevin Kirsche <kevin.kirsche@verizon.com> <kev.kirsche@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"
)

var (
	port         int
	timeout      int
	verbose      bool
	shownTLSInfo bool
)

var tlsNames = map[uint16]string{
	tls.VersionSSL30: "SSLv3", // 0x0300
	tls.VersionTLS10: "TLS1.0", // 0x0301
	tls.VersionTLS11: "TLS1.1", // 0x0302
	tls.VersionTLS12: "TLS1.2", // 0x0303
	tls.VersionTLS13: "TLS1.3", // 0x0304
}

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "sslcheck",
	Short: "sslcheck allows a user to check for supported SSL/TLS versions from SSLv3 up",
	Long: `sslcheck is designed to allow a user to check the versions of SSL or
TLS which are supported by a remote host or IP address. This supports SSLv3 up
to TLS1.2. The command may be used like so:

sslcheck www.google.com

sslcheck -p 443 www.google.com

sslcheck --port 443 www.google.com

sslcheck -t 10 www.google.com

sslcheck --timeout 10 www.google.com

sslcheck -v www.google.com

sslcheck --verbose www.google.com`,
	Run: func(cmd *cobra.Command, args []string) {
		timeoutStr := strconv.Itoa(timeout)
		timeoutDur, err := time.ParseDuration(timeoutStr + "s")
		if err != nil {
			panic(err)
		}

		dialer := &net.Dialer{
			Timeout: timeoutDur,
		}

		for _, ip := range args {
			fmt.Printf("Checking Host: %s.\n", ip)
			portString := strconv.Itoa(port)

			data := make(map[string]interface{})
			fmt.Println("Checking for version: TLS1.3")
			data["tls13"] = checkSSLVersionAndViewCert(ip, portString, dialer, tls.VersionTLS13)
			
			fmt.Println("Checking for version: TLS1.2")
			data["tls12"] = checkSSLVersionAndViewCert(ip, portString, dialer, tls.VersionTLS12)

			fmt.Println("Checking for version: TLS1.1")
			data["tls11"] = checkSSLVersionAndViewCert(ip, portString, dialer, tls.VersionTLS11)

			fmt.Println("Checking for version: TLS1.0")
			data["tls1"] = checkSSLVersionAndViewCert(ip, portString, dialer, tls.VersionTLS10)

			fmt.Println("Checking for version: SSLv3")
			data["ssl3"] = checkSSLVersionAndViewCert(ip, portString, dialer, tls.VersionSSL30)

			fmt.Printf("[TLS/SSL Versions] SSLv3: %t, TLS1.0: %t, TLS1.1: %t, TLS1.2: %t, TLS1.3: %t\n", data["ssl3"], data["tls1"], data["tls11"], data["tls12"], data["tls13"])
		}
	},
}

func checkSSLVersionAndViewCert(url, port string, d *net.Dialer, tlsVersion uint16) bool {
	dconn, err := d.Dial("tcp", url+":"+port)

	if err != nil {
		fmt.Printf("[Server Connection] TCP Connection to %s error: %s\n", err, url)
		return false
	}
	defer dconn.Close()

	config := tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tlsVersion,
		MaxVersion:         tlsVersion,
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_FALLBACK_SCSV,
		},
	}

	conn := tls.Client(dconn, &config)
	defer conn.Close()

	err = conn.Handshake()
	if err != nil {
		fmt.Printf("[TLS/SSL Handshake] %s to %s received error: %s\n", tlsNames[tlsVersion], url, err)
		return false
	}

	if verbose && !shownTLSInfo {
		PrintCertificateDetails(conn)
	}

	return true
}

// PrintCertificateDetails prints the details about a TLS / SSL Certificate
func PrintCertificateDetails(conn *tls.Conn) {
	state := conn.ConnectionState()
	for i, certState := range state.PeerCertificates {
		switch i {
		case 0:
			fmt.Println("Server key information:")
			fmt.Printf("\tCommon Name:\t %s\n", certState.Subject.CommonName)
			PrintStringSlice("\tOrganizational Unit:\t", certState.Subject.OrganizationalUnit)
			PrintStringSlice("\tOrganization:\t", certState.Subject.Organization)
			PrintStringSlice("\tCity:\t", certState.Subject.Locality)
			PrintStringSlice("\tState:\t", certState.Subject.Province)
			PrintStringSlice("\tCountry:", certState.Subject.Country)
			fmt.Println()
			fmt.Println("SSL Certificate Valid:")
			fmt.Printf("\tFrom:\t %s\n", certState.NotBefore.String())
			fmt.Printf("\tTo:\t %s\n", certState.NotAfter.String())
			fmt.Println()
			fmt.Println("Valid Certificate Domain Names:")
			for dns := range certState.DNSNames {
				fmt.Printf("\t%v\n", certState.DNSNames[dns])
			}
		case 1:
			fmt.Println("Issued by:")
			fmt.Printf("\t%s\n", certState.Subject.CommonName)
			PrintStringSlice("", certState.Subject.OrganizationalUnit)
			PrintStringSlice("", certState.Subject.Organization)
		default:
			continue
		}
	}

	shownTLSInfo = true
}

// PrintStringSlice prints out the title, followed by each item within the slice
// of strings in a comma separated list. It then prints a newline.
func PrintStringSlice(title string, slice []string) {
	fmt.Print(title)
	len := len(slice)
	for i, item := range slice {
		fmt.Print(item)
		if i < len-1 {
			fmt.Print(", ")
		}
	}
	fmt.Print("\n")
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports Persistent Flags, which, if defined here,
	// will be global for your application.

	RootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enables verbose mode")
	RootCmd.PersistentFlags().IntVarP(&timeout, "timeout", "t", 50, "Timeout is the maximum amount of time in seconds a dial will wait")
	RootCmd.PersistentFlags().IntVarP(&port, "port", "p", 443, "Port to check SSL/TLS versions of")
	// Cobra also supports local flags, which will only run
	// when this action is called directly.
}
