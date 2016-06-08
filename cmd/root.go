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
	port    int
	timeout int
	verbose bool
)

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
		tlsArray := []uint16{
			tls.VersionTLS12,
			tls.VersionTLS11,
			tls.VersionTLS10,
			tls.VersionSSL30,
		}

		tlsNames := map[uint16]string{
			tls.VersionSSL30: "SSLv3",
			tls.VersionTLS10: "TLS1.0",
			tls.VersionTLS11: "TLS1.1",
			tls.VersionTLS12: "TLS1.2",
		}

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
			shownTLSInfo := false
			for _, tlsVersion := range tlsArray {
				fmt.Printf("Checking for version: %s.\n", tlsNames[tlsVersion])
				tlsConfig := &tls.Config{
					MinVersion: tlsVersion,
					MaxVersion: tlsVersion,
				}

				portString := strconv.Itoa(port)

				conn, err := tls.DialWithDialer(dialer, "tcp", ip+":"+portString, tlsConfig)
				if err != nil {
					fmt.Println(err)
					break
				}
				defer conn.Close()

				if conn != nil {
					fmt.Printf("Version supported: %s.\n", tlsNames[tlsVersion])
					if verbose && !shownTLSInfo {
						shownTLSInfo = true
						hsErr := conn.Handshake()
						if hsErr != nil {
							fmt.Printf("Client connected, but the certificate failed.")
							break
						}
						state := conn.ConnectionState()
						for i, certState := range state.PeerCertificates {
							switch i {
							case 0:
								fmt.Println("Server key information:")
								fmt.Printf("\tCommon Name:\t %s\n\tOrganizational Unit:\t %v\n\tOrganizaiton:\t %v\n", certState.Subject.CommonName, certState.Subject.OrganizationalUnit, certState.Subject.Organization)
								fmt.Printf("\tCity:\t %v\n\tState:\t %v\n\tCountry: %v\n", certState.Subject.Locality, certState.Subject.Province, certState.Subject.Country)
								fmt.Printf("SSL Certificate Valid:\n\tFrom:\t %v\n\tTo:\t %v\n", certState.NotBefore, certState.NotAfter)
								fmt.Printf("Valid Certificate Domain Names:\n")
								for dns := range certState.DNSNames {
									fmt.Printf("\t%v\n", certState.DNSNames[dns])
								}
							case 1:
								fmt.Printf("Issued by:\n\t%v\n\t%v\n\t%v\n", certState.Subject.CommonName, certState.Subject.OrganizationalUnit, certState.Subject.Organization)
							default:
								break
							}
						}
					}
				}
			}
		}
	},
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
