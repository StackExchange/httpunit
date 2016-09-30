package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/StackExchange/httpunit"
	"github.com/StackExchange/httpunit/_third_party/github.com/BurntSushi/toml"
	"github.com/StackExchange/httpunit/_third_party/github.com/bradfitz/slice"
)

var (
	filter   = flag.String("filter", "", `if specified, only uses this IP address; may end with "." to filter by IPs that start with the filter`)
	no10     = flag.Bool("no10", false, "no RFC1918 addresses")
	hiera    = flag.String("hiera", "", "tests listeners members from the specified hieradata/sets.json file")
	tomlLoc  = flag.String("toml", "", "httpunit.toml location")
	verbose1 = flag.Bool("v", false, "verbose output: show successes")
	verbose2 = flag.Bool("vv", false, "more verbose output: show -header, cert details")
	header   = flag.String("header", "X-Request-Guid", "an HTTP to header to print in verbose mode")
	timeout  = flag.Duration("timeout", httpunit.Timeout, "connection timeout")
	ipMap    = flag.String("ipmap", "", `override or set one entry if the IPs table, in "key=value" format, where value is a JSON array of strings; for example: -ipmap='BASEIP=["10.2.3.", "1.4.5."]'`)
	tags     = flag.String("tags", "", "if specified, only run plans that are tagged with these tags. Use comma seperated to include mutiple tags, e.g. \"normal,extended\"")
	protos   = flag.String("protos", "", "if specified, only run tests that use the designated protocol. Valid choices are: http,https,tcp,tcp4,tcp6,udp,udp4,udp6,ip,ip4,ip6. e.g. \"http,https\"")
)

func printNames(x []pkix.AttributeTypeAndValue) []string {
	var r []string
	for _, v := range x {
		r = append(r, v.Value.(string))
	}
	return r
}

func printStringsIfExist(w *bufio.Writer, label string, list []string) {
	switch {
	case len(list) == 1:
		fmt.Fprintf(w, `%s: %q`, label, list[0])
	case len(list) > 1:
		fmt.Fprintf(w, `%s: %q`, label, list)
		//fmt.Fprintf(w, `%s: "{%s"}`, label, strings.Join(list, `" "`))
	default:
		// do nothing.
	}
}

func printCert(w *bufio.Writer, c *x509.Certificate) {
	h := "\n\t\t"
	fmt.Fprintf(w, h+"expires: %v", c.NotAfter)
	fmt.Fprintf(w, h+"serial: %d", c.SerialNumber)
	fmt.Fprintf(w, h+"fingerprint: %x", sha1.Sum(c.Raw))
	fmt.Fprintf(w, h+"version: %d", c.Version)
	fmt.Fprintf(w, h+"domains: %q", c.DNSNames)
	if len(c.EmailAddresses) > 0 {
		fmt.Fprintf(w, h+"emails: %q", c.EmailAddresses)
	}
	if len(c.IPAddresses) > 0 {
		fmt.Fprintf(w, h+"IPs: %q", c.IPAddresses)
	}
	printStringsIfExist(w, h+"Names", printNames(c.Issuer.Names))
	printStringsIfExist(w, h+"ExtraNames", printNames(c.Issuer.ExtraNames))
	printStringsIfExist(w, h+"Country", c.Issuer.Country)
	printStringsIfExist(w, h+"Organization", c.Issuer.Organization)
	printStringsIfExist(w, h+"OrganizationalUnit", c.Issuer.OrganizationalUnit)
	printStringsIfExist(w, h+"Locality", c.Issuer.Locality)
	printStringsIfExist(w, h+"Province", c.Issuer.Province)

}

func doMain() int {
	var seen_error int
	flag.Parse()
	if *verbose2 {
		*verbose1 = true
	}
	plans := &httpunit.Plans{
		IPs: make(httpunit.IPMap),
	}
	var err error
	if *timeout > 0 {
		httpunit.Timeout = *timeout
	}
	if *tomlLoc != "" {
		if _, err := toml.DecodeFile(*tomlLoc, &plans); err != nil {
			log.Fatal(err)
		}
	}
	if *hiera != "" {
		p, err := httpunit.ExtractHiera(*hiera)
		plans.Plans = append(plans.Plans, p...)
		if err != nil {
			log.Fatal(err)
		}
	}
	if args := flag.Args(); len(args) > 0 {
		if plans.Plans != nil {
			log.Fatal("cannot manually specify URLs with other modes")
		}
		u := args[0]
		args = args[1:]
		tp := httpunit.TestPlan{
			Label: u,
		}
		if !strings.Contains(u, "://") {
			u = "http://" + u
		}
		tp.URL = u
		if len(args) > 0 {
			if args[0] != "" {
				tp.IPs = []string{args[0]}
			}
			args = args[1:]
		}
		if len(args) > 0 {
			code, err := strconv.Atoi(args[0])
			if err != nil {
				log.Fatalf("bad status code: %v: %v", args[0], err)
			}
			args = args[1:]
			tp.Code = code
		}
		if len(args) > 0 {
			_, err := regexp.Compile(args[0])
			if err != nil {
				log.Fatalf("bad regex: %v: %v", args[0], err)
			}
			tp.Regex = args[0]
			args = args[1:]
		}
		if len(args) > 0 {
			log.Fatalf("too many arguments")
		}
		plans.Plans = []*httpunit.TestPlan{&tp}
	}
	if *ipMap != "" {
		sp := strings.SplitN(*ipMap, "=", 2)
		if len(sp) != 2 {
			log.Fatalf("expected key=value in -ipmap")
		}
		var vals []string
		if err := json.Unmarshal([]byte(sp[1]), &vals); err != nil {
			log.Fatalf("ipmap: %v", err)
		}
		plans.IPs[sp[0]] = vals
	}
	if len(plans.Plans) == 0 {
		log.Fatalf("no tests specified")
	}
	var tagFilter []string
	if *tags != "" {
		tagFilter = strings.Split(*tags, ",")
	}
	var protoFilter []string
	if *protos != "" {
		protoFilter = strings.Split(*protos, ",")
	}
	rch, count, err := plans.Test(*filter, *no10, tagFilter, protoFilter)
	if err != nil {
		log.Fatal(err)
	}
	var res httpunit.Results
	delay := time.Second / 2
	next := time.After(delay)
	got := 0
	start := time.Now()

Loop:
	for {
		select {
		case <-next:
			fmt.Fprintf(os.Stderr, "%v of %v done in %v\n", got, count, time.Since(start))
			next = time.After(delay)
		case r, ok := <-rch:
			if !ok {
				fmt.Fprintf(os.Stderr, "%v of %v done in %v\n", got, count, time.Since(start))
				break Loop
			}
			res = append(res, r)
			got++
		}
	}

	pidx := make(map[*httpunit.TestPlan]int)
	for i, p := range plans.Plans {
		pidx[p] = i
	}
	slice.Sort(res, func(i, j int) bool {
		a := res[i].Plan
		b := res[j].Plan
		pa := pidx[a]
		pb := pidx[b]
		if pa != pb {
			return pa < pb
		}
		ai := res[i].Case.IP
		bi := res[j].Case.IP
		if len(ai) != len(bi) {
			return len(ai) < len(bi)
		}
		for k, v := range ai {
			if bi[k] != v {
				return ai[k] < bi[k]
			}
		}
		return false
	})
	for _, r := range res {
		fromDNS := "IP"
		if r.Case.FromDNS {
			fromDNS = "DNS"
		}
		ip := fmt.Sprintf("%v=%v", fromDNS, r.Case.IP)
		var status string
		var verbose bytes.Buffer
		ver := bufio.NewWriter(&verbose)
		if r.Case.ExpectCode > 0 {
			status += fmt.Sprint(r.Case.ExpectCode)
		}
		if r.Case.ExpectText != "" {
			status += " T"
		}
		if r.Case.ExpectRegex != nil {
			status += " R"
		}
		if status != "" {
			status = " (" + status + ")"
		}
		if !*verbose1 && r.Result.Result == nil {
			continue
		}
		if *verbose2 {
			if resp := r.Result.Resp; resp != nil {
				if *header != "" {
					if h := resp.Header.Get(*header); h != "" {
						fmt.Fprintf(ver, "\n\theader %s: %s", *header, h)
					}
				}
				if t := resp.TLS; t != nil {
					for i, c := range t.PeerCertificates {
						fmt.Fprintf(ver, "\n\tcert %v:", i)
						printCert(ver, c)

					}
					for j, v := range t.VerifiedChains {
						for i, c := range v {
							fmt.Fprintf(ver, "\n\tVerified chain %d.%d:", j, i)
							printCert(ver, c)
						}
					}
				}
			}

		}
		ver.Flush()
		fmt.Printf("==== %v: %v %s%s%s\n", r.Plan.Label, r.Plan.URL, ip, status, verbose.String())
		if r.Result.Result != nil {
			fmt.Println("ERROR:", r.Result.Result)
			seen_error = 1
		}
	}
	return seen_error
}

func main() {
	os.Exit(doMain()) // http://stackoverflow.com/a/27629493/71978
}
