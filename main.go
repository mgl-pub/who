package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/mitchellh/go-homedir"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"who/common"
	"who/xdb"
)

// Units.
const (
	_        = iota
	KB int64 = 1 << (10 * iota)
	MB
	GB
	TB
)

var (
	cert    string
	key     string
	ca      string
	port    string
	name    string
	verbose bool
)

func init() {
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	flag.StringVar(&cert, "cert", "", "give me a certificate")
	flag.StringVar(&key, "key", "", "give me a key")
	flag.StringVar(&ca, "cacert", "", "give me a CA chain, enforces mutual TLS")
	flag.StringVar(&port, "port", getEnv("WHO_PORT_NUMBER", "8080"), "give me a port number")
	flag.StringVar(&name, "name", os.Getenv("WHO_NAME"), "give me a name")
}

var upgrade = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

func printHelp() {
	fmt.Printf("ip2region xdb searcher\n")
	fmt.Printf("%s [command] [command options]\n", os.Args[0])
	fmt.Printf("Command: \n")
	fmt.Printf("  search    search input test\n")
	fmt.Printf("  bench     search bench test\n")
}

func getRegion(ip string) string {
	var err error
	var dbFile, cachePolicy = "", "vectorIndex"

	dir, _ := os.Getwd()

	println("dir", dir)
	if dir != "/" {
		dbFile = "/data/ip2region.xdb"
	} else {
		dbFile = dir + "/data/ip2region.xdb"
	}

	fmt.Println(homedir.Expand("/data/ip2region.xdb"))
	fmt.Println(dbFile)
	if dbFile == "" {
		fmt.Printf("%s search [command options]\n", os.Args[0])
		fmt.Printf("options:\n")
		fmt.Printf(" --db string              ip2region binary xdb file path\n")
		fmt.Printf(" --cache-policy string    cache policy: file/vectorIndex/content\n")
		return ""
	}

	dbPath, err := homedir.Expand(dbFile)
	if err != nil {
		fmt.Printf("invalid xdb file path `%s`: %s", dbFile, err)
		return ""
	}

	// create the searcher with the cache policy setting
	searcher, err := createSearcher(dbPath, cachePolicy)
	if err != nil {
		fmt.Printf("failed to create searcher: %s\n", err.Error())
		return ""
	}
	defer func() {
		searcher.Close()
		fmt.Printf("searcher test program exited, thanks for trying\n")
	}()

	tStart := time.Now()
	region, err := searcher.SearchByStr(ip)
	if err != nil {
		fmt.Printf("\x1b[0;31m{err: %s, ioCount: %d}\x1b[0m\n", err.Error(), searcher.GetIOCount())
	} else {
		fmt.Printf("\x1b[0;32m{region: %s, ioCount: %d, took: %s}\x1b[0m\n", region, searcher.GetIOCount(), time.Since(tStart))
	}

	return region
}

func testSearch() {
	var err error
	var dbFile, cachePolicy = "", "vectorIndex"
	for i := 2; i < len(os.Args); i++ {
		r := os.Args[i]
		if len(r) < 5 {
			continue
		}

		if strings.Index(r, "--") != 0 {
			continue
		}

		var sIdx = strings.Index(r, "=")
		if sIdx < 0 {
			fmt.Printf("missing = for args pair '%s'\n", r)
			return
		}

		switch r[2:sIdx] {
		case "db":
			dbFile = r[sIdx+1:]
		case "cache-policy":
			cachePolicy = r[sIdx+1:]
		default:
			fmt.Printf("undefined option `%s`\n", r)
			return
		}
	}

	dbFile = "/home/hotpot/Develop/Workspaces/2022/who/data/ip2region.xdb"
	fmt.Println(homedir.Expand("/data/ip2region.xdb"))
	fmt.Println(dbFile)
	if dbFile == "" {
		fmt.Printf("%s search [command options]\n", os.Args[0])
		fmt.Printf("options:\n")
		fmt.Printf(" --db string              ip2region binary xdb file path\n")
		fmt.Printf(" --cache-policy string    cache policy: file/vectorIndex/content\n")
		return
	}

	dbPath, err := homedir.Expand(dbFile)
	if err != nil {
		fmt.Printf("invalid xdb file path `%s`: %s", dbFile, err)
		return
	}

	// create the searcher with the cache policy setting
	searcher, err := createSearcher(dbPath, cachePolicy)
	if err != nil {
		fmt.Printf("failed to create searcher: %s\n", err.Error())
		return
	}
	defer func() {
		searcher.Close()
		fmt.Printf("searcher test program exited, thanks for trying\n")
	}()

	fmt.Printf(`ip2region xdb searcher test program, cachePolicy: %s
type 'quit' to exit
`, cachePolicy)
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("ip2region>> ")
		str, err := reader.ReadString('\n')
		if err != nil {
			log.Fatalf("failed to read string: %s", err)
		}

		line := strings.TrimSpace(strings.TrimSuffix(str, "\n"))
		if len(line) == 0 {
			continue
		}

		if line == "quit" {
			break
		}

		tStart := time.Now()
		region, err := searcher.SearchByStr(line)
		if err != nil {
			fmt.Printf("\x1b[0;31m{err: %s, ioCount: %d}\x1b[0m\n", err.Error(), searcher.GetIOCount())
		} else {
			fmt.Printf("\x1b[0;32m{region: %s, ioCount: %d, took: %s}\x1b[0m\n", region, searcher.GetIOCount(), time.Since(tStart))
		}
	}
}

func testBench() {
	var err error
	var dbFile, srcFile, cachePolicy = "", "", "vectorIndex"
	for i := 2; i < len(os.Args); i++ {
		r := os.Args[i]
		if len(r) < 5 {
			continue
		}

		if strings.Index(r, "--") != 0 {
			continue
		}

		var sIdx = strings.Index(r, "=")
		if sIdx < 0 {
			fmt.Printf("missing = for args pair '%s'\n", r)
			return
		}

		switch r[2:sIdx] {
		case "db":
			dbFile = r[sIdx+1:]
		case "src":
			srcFile = r[sIdx+1:]
		case "cache-policy":
			cachePolicy = r[sIdx+1:]
		default:
			fmt.Printf("undefined option `%s`\n", r)
			return
		}
	}

	if dbFile == "" || srcFile == "" {
		fmt.Printf("%s bench [command options]\n", os.Args[0])
		fmt.Printf("options:\n")
		fmt.Printf(" --db string              ip2region binary xdb file path\n")
		fmt.Printf(" --src string             source ip text file path\n")
		fmt.Printf(" --cache-policy string    cache policy: file/vectorIndex/content\n")
		return
	}

	dbPath, err := homedir.Expand(dbFile)
	if err != nil {
		fmt.Printf("invalid xdb file path `%s`: %s", dbFile, err)
		return
	}

	searcher, err := createSearcher(dbPath, cachePolicy)
	if err != nil {
		fmt.Printf("failed to create searcher: %s\n", err.Error())
		return
	}
	defer func() {
		searcher.Close()
	}()

	handle, err := os.OpenFile(srcFile, os.O_RDONLY, 0600)
	if err != nil {
		fmt.Printf("failed to open source text file: %s\n", err)
		return
	}

	var count, tStart, costs = int64(0), time.Now(), int64(0)
	var scanner = bufio.NewScanner(handle)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		var l = strings.TrimSpace(strings.TrimSuffix(scanner.Text(), "\n"))
		var ps = strings.SplitN(l, "|", 3)
		if len(ps) != 3 {
			fmt.Printf("invalid ip segment line `%s`\n", l)
			return
		}

		sip, err := xdb.CheckIP(ps[0])
		if err != nil {
			fmt.Printf("check start ip `%s`: %s\n", ps[0], err)
			return
		}

		eip, err := xdb.CheckIP(ps[1])
		if err != nil {
			fmt.Printf("check end ip `%s`: %s\n", ps[1], err)
			return
		}

		if sip > eip {
			fmt.Printf("start ip(%s) should not be greater than end ip(%s)\n", ps[0], ps[1])
			return
		}

		mip := xdb.MidIP(sip, eip)
		for _, ip := range []uint32{sip, xdb.MidIP(sip, mip), mip, xdb.MidIP(mip, eip), eip} {
			sTime := time.Now()
			region, err := searcher.Search(ip)
			if err != nil {
				fmt.Printf("failed to search ip '%s': %s\n", xdb.Long2IP(ip), err)
				return
			}

			costs += time.Since(sTime).Nanoseconds()

			// check the region info
			if region != ps[2] {
				fmt.Printf("failed Search(%s) with (%s != %s)\n", xdb.Long2IP(ip), region, ps[2])
				return
			}

			count++
		}
	}

	cost := time.Since(tStart)
	fmt.Printf("Bench finished, {cachePolicy: %s, total: %d, took: %s, cost: %d μs/op}\n",
		cachePolicy, count, cost, costs/count/1000)
}

func createSearcher(dbPath string, cachePolicy string) (*xdb.Searcher, error) {
	switch cachePolicy {
	case "nil", "file":
		return xdb.NewWithFileOnly(dbPath)
	case "vectorIndex":
		vIndex, err := xdb.LoadVectorIndexFromFile(dbPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load vector index from `%s`: %w", dbPath, err)
		}

		return xdb.NewWithVectorIndex(dbPath, vIndex)
	case "content":
		cBuff, err := xdb.LoadContentFromFile(dbPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load content from '%s': %w", dbPath, err)
		}

		return xdb.NewWithBuffer(cBuff)
	default:
		return nil, fmt.Errorf("invalid cache policy `%s`, options: file/vectorIndex/content", cachePolicy)
	}
}

//func main() {
//testGetRegion("116.95.87.110")
/*testSearch()
if len(os.Args) < 2 {
	printHelp()
	return
}

// set the log flag
log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
switch strings.ToLower(os.Args[1]) {
case "search":
	testSearch()
case "bench":
	testBench()
default:
	printHelp()
}*/
//}

func main() {
	dir, _ := os.Getwd()

	println("dir", dir)
	flag.Parse()
	mux := http.NewServeMux()
	mux.Handle("/data", handle(dataHandler, verbose))
	mux.Handle("/echo", handle(echoHandler, verbose))
	mux.Handle("/bench", handle(benchHandler, verbose))
	mux.Handle("/api", handle(apiHandler, verbose))
	mux.Handle("/health", handle(healthHandler, verbose))
	mux.Handle("/", handle(whoHandler, verbose))

	if cert == "" || key == "" {
		log.Printf("Starting up on port %s", port)

		log.Fatal(http.ListenAndServe(":"+port, mux))
	}

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	if len(ca) > 0 {
		server.TLSConfig = setupMutualTLS(ca)
	}

	log.Printf("Starting up with TLS on port %s", port)

	log.Fatal(server.ListenAndServeTLS(cert, key))
}

func setupMutualTLS(ca string) *tls.Config {
	clientCACert, err := os.ReadFile(ca)
	if err != nil {
		log.Fatal(err)
	}

	clientCertPool := x509.NewCertPool()
	clientCertPool.AppendCertsFromPEM(clientCACert)

	tlsConfig := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  clientCertPool,
		//PreferServerCipherSuites: true,
		MinVersion: tls.VersionTLS12,
	}

	return tlsConfig
}

func handle(next http.HandlerFunc, verbose bool) http.Handler {
	if !verbose {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next(w, r)

		// <remote_IP_address> - [<timestamp>] "<request_method> <request_path> <request_protocol>" -
		log.Printf("%s - - [%s] \"%s %s %s\" - -", r.RemoteAddr, time.Now().Format("02/Jan/2006:15:04:05 -0700"), r.Method, r.URL.Path, r.Proto)
	})
}

func benchHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Content-Type", "text/plain")
	_, _ = fmt.Fprint(w, "1")
}

func echoHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrade.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}

	for {
		messageType, p, err := conn.ReadMessage()
		if err != nil {
			return
		}

		printBinary(p)
		err = conn.WriteMessage(messageType, p)
		if err != nil {
			return
		}
	}
}

func printBinary(s []byte) {
	fmt.Printf("Received b:")
	for n := 0; n < len(s); n++ {
		fmt.Printf("%d,", s[n])
	}
	fmt.Printf("\n")
}

func dataHandler(w http.ResponseWriter, r *http.Request) {
	u, _ := url.Parse(r.URL.String())
	queryParams := u.Query()

	size, err := strconv.ParseInt(queryParams.Get("size"), 10, 64)
	if err != nil {
		size = 1
	}
	if size < 0 {
		size = 0
	}

	unit := queryParams.Get("unit")
	switch strings.ToLower(unit) {
	case "kb":
		size *= KB
	case "mb":
		size *= MB
	case "gb":
		size *= GB
	case "tb":
		size *= TB
	}

	attachment, err := strconv.ParseBool(queryParams.Get("attachment"))
	if err != nil {
		attachment = false
	}

	content := &common.ContentReader{Size: size}

	if attachment {
		w.Header().Set("Content-Disposition", "Attachment")
		http.ServeContent(w, r, "data.txt", time.Now(), content)
		return
	}

	if _, err := io.Copy(w, content); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func getClientIp(req *http.Request) string {
	ip := req.RemoteAddr
	if len(req.Header.Get("X-Forwarded-For")) > 0 {
		ip = req.Header.Get("X-Forwarded-For")
	}
	if len(req.Header.Get("X-Real-Ip")) > 0 {
		ip = req.Header.Get("X-Real-Ip")
	}
	return ip
}

func whoHandler(w http.ResponseWriter, req *http.Request) {
	u, _ := url.Parse(req.URL.String())
	wait := u.Query().Get("wait")
	if len(wait) > 0 {
		duration, err := time.ParseDuration(wait)
		if err == nil {
			time.Sleep(duration)
		}
	}

	if name != "" {
		_, _ = fmt.Fprintln(w, "Name:", name)
	}

	hostname, _ := os.Hostname()
	_, _ = fmt.Fprintln(w, "Hostname:", hostname)

	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		// handle err
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			_, _ = fmt.Fprintln(w, "IP:", ip)
		}
	}

	remoteIP := getClientIp(req)
	var region string

	if strings.Contains(remoteIP, "::1") || strings.Contains(remoteIP, "127.0.0.1") {
		region = "本地地址"
	} else {
		getRegion(getClientIp(req))
	}
	_, _ = fmt.Fprintln(w, "YourIpAddr:")
	_, _ = fmt.Fprintln(w, "YourRegion:", region)

	if err := req.Write(w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func apiHandler(w http.ResponseWriter, req *http.Request) {
	hostname, _ := os.Hostname()

	data := struct {
		Hostname string      `json:"hostname,omitempty"`
		IP       []string    `json:"ip,omitempty"`
		Headers  http.Header `json:"headers,omitempty"`
		URL      string      `json:"url,omitempty"`
		Host     string      `json:"host,omitempty"`
		Method   string      `json:"method,omitempty"`
		Name     string      `json:"name,omitempty"`
		Region   string      `json:"region,omitempty"`
	}{
		Hostname: hostname,
		IP:       []string{},
		Headers:  req.Header,
		URL:      req.URL.RequestURI(),
		Host:     req.Host,
		Method:   req.Method,
		Name:     name,
		Region:   "111111",
	}

	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		// handle err
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil {
				data.IP = append(data.IP, ip.String())
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type healthState struct {
	StatusCode int
}

var (
	currentHealthState = healthState{http.StatusOK}
	mutexHealthState   = &sync.RWMutex{}
)

func healthHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodPost {
		var statusCode int

		if err := json.NewDecoder(req.Body).Decode(&statusCode); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		fmt.Printf("Update health check status code [%d]\n", statusCode)

		mutexHealthState.Lock()
		defer mutexHealthState.Unlock()
		currentHealthState.StatusCode = statusCode
	} else {
		mutexHealthState.RLock()
		defer mutexHealthState.RUnlock()
		w.WriteHeader(currentHealthState.StatusCode)
	}
}

func getEnv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}
