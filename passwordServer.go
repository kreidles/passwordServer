/*
* passwordServer
* 
* An http server that encrypts passwords with SHA512 via a REST API
*
* usage:
*   passwordServer [-p=<port_number>] [-q=<queue_size>]
*/
package main

import (
	"os"
	"os/signal"
	"syscall"
	"fmt"
	"flag"
	// "time"
	"sync/atomic"
	"net"
    "net/http"
    // "crypto/sha512"
    "strings"
    "strconv"
    "regexp"
)

// a password hash request
type PasswordHashRequest struct {
	Password string

}

// the total number of requests since server startup
var totalRequests uint64 = 0
var totalRequestTime uint64 = 0

// the queue of password hash requests
var WorkQueue = make(chan PasswordHashRequest, 100)

// getJobId parses the job id from URI's of the form "hash/<jobid>/"
// note, there are better third party routers (mux, etc.) that could handle this
// for us, but it does not appear to be supported in the net/http package
func getJobId(uri string) int {
	p := strings.Split(uri, "/")
    if len(p) == 1 {
        return -1
    } else if len(p) > 1 {
        code, err := strconv.Atoi(p[0])
        if err == nil {
            return code
        } else {
            return -1
        }
    } else {
        return -1
    }
}

func getPasswordHash(jobId int) string {
	return ""
}

// readPasswordHash returns the password hash if the job has finished processing,
// or not found
func readPasswordHash(w http.ResponseWriter, r *http.Request, jobId int) {
	if (r.Method != "GET") {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}

	fmt.Println(jobId)
	// For the specified job id, find the password hash request 
	if (jobId >= 0) {
		// return the password hash if processed, otherwise return not found
		hash := getPasswordHash(jobId)
		if (hash == "") {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		} else {
			fmt.Fprintf(w, hash)
		}
	} else {
		http.Error(w, "{\"msg\": \"No job id specified\"}", http.StatusBadRequest)
	}
}

// createPasswordHash handles creation and retrieval of password hash requests.
// For POST requests, 
func createPasswordHash(w http.ResponseWriter, r *http.Request) {
	if (r.Method != "POST") {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}

	// get the password from the post parameters 
	r.ParseForm()
	password := r.FormValue("password")
	if password != "" {
		// request must include a password
		http.Error(w, "{\"msg\": \"No password specified\"}", http.StatusBadRequest)

	} else {
		// increment the number of password hash requests
		atomic.AddUint64(&totalRequests, 1)
		// TODO: parse add request to queue
	    fmt.Fprintf(w, "Hi there, I love %s!", r.URL.Path[1:])
	}	
}

// getStats returns a JSON object including the total hash requests since server start 
// and the average time of a hash request in milliseconds.  Time of a hash request is 
// calculated as the elapsed time from the request being added to the work queue to the
// completion of the request
func getStats(w http.ResponseWriter, r *http.Request) {
	if (r.Method != "GET") {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}

    fmt.Fprintf(w, "{\"total\": %d, \"average\": %f}", 
    	totalRequests, float64(totalRequestTime) / float64(totalRequests))
}

// shutdown blocks until all password hash requests in the work queue have
// been processed.
func shutdown() {
    fmt.Println("shutting down...")
}

// route performs pattern matching on the URI and calls the appropriate
// function to handle the request.  Needed some regex matching for the 
// "hash" route, so decided to handle all of the routing in one place
// rather than rely on the net/http builtin HandleFunc.  
//
// This would be better handled by mux or other 3rd party routing library,
// but I couldn't find any regex-based routing built into Go
func route(w http.ResponseWriter, r *http.Request) {

	var statsRoute = regexp.MustCompile(`^/stats/*$`) 
	var newHashRoute = regexp.MustCompile(`^/hash/*$`)
	var existingHashRoute = regexp.MustCompile(`^/hash/(?P<jobId>\d+)/*$`)

    switch {
    case statsRoute.MatchString(r.URL.Path):
        getStats(w, r)
    case newHashRoute.MatchString(r.URL.Path):
        createPasswordHash(w, r)
    case existingHashRoute.MatchString(r.URL.Path):
    	res := existingHashRoute.FindStringSubmatch(r.URL.Path)
    	jobId, _ := strconv.Atoi(res[1])
    	readPasswordHash(w, r, jobId)
    default:
        http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
    }
}

// main starts the service on port 8080, unless the user specifies an alternate port. 
func main() {

	// parse command line flags
	portPtr := flag.Int("p", 8080, "the server port number")
	queueSizePtr := flag.Int("q", 100, "size of the request queue")
	flag.Parse()

	// set the port
	port := fmt.Sprintf(":%d", *portPtr)
	// intialize the work queue
	WorkQueue = make(chan PasswordHashRequest, *queueSizePtr)


    // create a listener channel on the specified port.  We create this
    // separately from the http.Serve call so we can shut down the port on system interrupts
    // and prevent additional requests from coming in.
    l, err := net.Listen("tcp", port)
	if err != nil {
	    fmt.Println("Cannot listen on port ", port, " - ", err)
	    os.Exit(1)
	}

    // register handler for system interrupts so we can wait for the work queue
    // to clear before shutting down
    c := make(chan os.Signal, 1)                                       
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)                               
	go func() {
		<-c
		l.Close()
		shutdown()
		os.Exit(0)                                                                                                                    
	}()    

	// set up the routes - specific uri's matched within the route function
	http.HandleFunc("/", route)

    // start the http server
    http.Serve(l, nil)

}
