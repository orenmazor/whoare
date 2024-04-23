/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "whoare",
	Short: "Look up a domain name's official name servers and query these for information",
	Run:   lookup,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringP("domain", "n", "", "The domain to investigate")
	rootCmd.MarkFlagRequired("domain")
}

func lookup(cmd *cobra.Command, args []string) {
	domain, _ := cmd.Flags().GetString("domain")

	whois_raw, err := whois.Whois(domain)
	if err != nil {
		slog.Error(err.Error())
		return
	}

	result, err := whoisparser.Parse(whois_raw)

	slog.Info("Got Whois information", "domain", domain)
	for _, ns := range result.Domain.NameServers {

		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Millisecond * time.Duration(10000),
				}
				return d.DialContext(ctx, network, fmt.Sprintf("%s:53", ns))
			},
		}
		ip, _ := r.LookupHost(context.Background(), domain)

		slog.Info("Resolution", "domain", domain, "NS", ns, "A", strings.Join(ip, ", "))
	}
}
