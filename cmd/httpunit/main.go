package main

import (
	"crypto/sha1"
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
	timeout  = flag.Duration("timeout", time.Second*3, "connection timeout")
	ipMap    = flag.String("ipmap", "", `override or set one entry if the IPs table, in "key=value" format, where value is a JSON array of strings; for example: -ipmap='BASEIP=["10.2.3.", "1.4.5."]'`)
)

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
	rch, count, err := plans.Test(*filter, *no10)
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
		var status, verbose string
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
						verbose += fmt.Sprintf("\n\theader %s: %s", *header, h)
					}
				}
				if t := resp.TLS; t != nil {
					for i, c := range t.PeerCertificates {
						verbose += fmt.Sprintf("\n\tcert %v:\n\t\texpires: %v\n\t\tfingerprint: %x\n\t\tdomains: %q", i, c.NotAfter, sha1.Sum(c.Raw), c.DNSNames)
					}
				}
			}

		}
		fmt.Printf("==== %v: %v %s%s%s\n", r.Plan.Label, r.Plan.URL, ip, status, verbose)
		if r.Result.Result != nil {
			fmt.Println("ERROR:", r.Result.Result)
      seen_error = 1
		}
	}
  return seen_error
}

func main() {
    os.Exit(doMain())  // http://stackoverflow.com/a/27629493/71978
}
