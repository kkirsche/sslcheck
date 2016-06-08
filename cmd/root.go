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
	"os"
	"strconv"

	"github.com/spf13/cobra"
)

var port int

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "sslcheck",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
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

		for _, ip := range args {
			fmt.Printf("Checking Host: %s.\n", ip)
			for _, tlsVersion := range tlsArray {
				fmt.Printf("Checking for version: %s.\n", tlsNames[tlsVersion])
				tlsConfig := &tls.Config{
					MinVersion: tlsVersion,
					MaxVersion: tlsVersion,
				}

				portString := strconv.Itoa(port)

				conn, err := tls.Dial("tcp", ip+":"+portString, tlsConfig)
				if err != nil {
					fmt.Println(err)
				}

				if conn != nil {
					fmt.Printf("Version supported: %s.\n", tlsNames[tlsVersion])
					conn.Close()
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

	RootCmd.PersistentFlags().IntVarP(&port, "port", "p", 443, "Port to check SSL/TLS versions of")
	// Cobra also supports local flags, which will only run
	// when this action is called directly.
}
