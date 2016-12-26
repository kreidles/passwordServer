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
	"time"
	"sync"
	"sync/atomic"
	"net"
    "net/http"
    "crypto/sha512"
    "strconv"
    "regexp"
)

/**** GLOBALS ****/
// password hash work queue
var PasswordHashWorkQueue chan PasswordHashRequest = nil
// create a thread-safe hashmap to store results
var PasswordResultMap = NewSyncMap()
// the total number of requests since server startup, also used as the unique job id
var totalRequests uint64 = 0
// total time spent processing password hashes
var totalRequestTime uint64 = 0

/**** Class/struct definitions ****/

/* mutex locked hashmap to store password hash results */
type SyncMap struct {
	lock sync.RWMutex
	m    map[uint64]string
}
// create a thread-safe hash map
func NewSyncMap() *SyncMap {
	return &SyncMap{m: make(map[uint64]string)}
}
// get a value from the map
func (s *SyncMap) Get(key uint64) (string, bool) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	value, ok := s.m[key]
	return value, ok
}
// set a value in the map
func (s *SyncMap) Set(key uint64, value string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.m[key] = value
}
// END SyncMap definition


/* a password hash job */
type PasswordHashRequest struct {
	jobId uint64
	password string
	started time.Time
}

/* worker to process hash requests */
type PasswordHashWorker struct {
	id int
	workQueue chan PasswordHashRequest
	quitChannel chan bool
	results *SyncMap
}
// create a worker
func NewPasswordHashWorker(id int, workQueue chan PasswordHashRequest, results *SyncMap) *PasswordHashWorker {
	return &PasswordHashWorker {
		id: id,
		workQueue: workQueue,
		quitChannel: make(chan bool, 1),
		results: results,
	}
}
// start starts a PasswordHashWorker.  The worker runs a go routine that reads from the work queue and 
// processes a password hash job.  It first sleeps for 5 seconds and then calculates
// the SHA215 hash of the job password.  Also updates the total processing time
// for password hash requests
func (w *PasswordHashWorker) start() {
	fmt.Println("starting worker", w.id)
	go func() {
		for {
	        select {
	        case work := <-w.workQueue:
		      	// process password hash jobs
		      	fmt.Println("worker", w.id, " processing password ", work.password)
		        time.Sleep(5 * time.Second)
		        // encrypt the password and store in the results
		        passwordBytes := []byte(work.password)
		        var hash = sha512.New()
				w.results.Set(work.jobId, string(hash.Sum(passwordBytes)))

				// calculate the total processing time for this job (includes queue wait time)
				elapsed := time.Since(work.started)
				// update the total processing time since server startup
				atomic.AddUint64(&totalRequestTime, uint64(elapsed))

	        case <-w.quitChannel:
		        // stop the worker
		        fmt.Printf("worker%d stopping\n", w.id)
		        return
	        }
	    }
    } ()
}
// stop a worker - add a stop signal to the quit channel
func (w *PasswordHashWorker) stop() {
	w.quitChannel <- true
}
// END PasswordHashWorker definition



// readPasswordHash returns the password hash if the job has finished processing,
// otherwise not found
func readPasswordHash(w http.ResponseWriter, r *http.Request, jobId uint64) {
	if (r.Method != "GET") {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}

	// For the specified job id, find the password hash request 
	if (jobId > 0) {
		// return the password hash if processed, otherwise return not found
		hash, _ := PasswordResultMap.Get(jobId)
		if (hash == "") {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		} else {
			fmt.Fprintf(w, hash)
		}
	} else {
		http.Error(w, "{\"msg\": \"No job id specified\"}", http.StatusBadRequest)
	}
}

// createPasswordHash creates non-blocking password hash jobs (which take some time to process)
// and returns the corresponding job id immediately
func createPasswordHash(w http.ResponseWriter, r *http.Request) {
	if (r.Method != "POST") {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	// get the password from the post parameters 
	r.ParseForm()
	password := r.FormValue("password")
	if password == "" {
		// request must include a password
		http.Error(w, "{\"msg\": \"No password specified\"}", http.StatusBadRequest)
	} else {
		// increment the number of password hash requests
		jobId := atomic.AddUint64(&totalRequests, 1)
		// add a new password hash job to the queue
		started := time.Now()
		job := PasswordHashRequest{jobId: jobId, password: password, started: started}
  		PasswordHashWorkQueue <- job
		// return the jobId
	    fmt.Fprintf(w, "%d", jobId)
	}	
}

// getStats returns a JSON object including the total hash requests since server start 
// and the average time of a hash request in milliseconds.  Time of a hash request is 
// calculated as the elapsed time from the request being added to the work queue to the
// completion of the request
func getStats(w http.ResponseWriter, r *http.Request) {
	if (r.Method != "GET") {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	// read the global request counter and total time
	requestCount := atomic.LoadUint64(&totalRequests)
	requestTime := atomic.LoadUint64(&totalRequestTime)

    fmt.Fprintf(w, "{\"total\": %d, \"average\": %f}", 
    	requestCount, float64(requestTime) / float64(requestCount))
}

// route performs pattern matching on the URI and calls the appropriate
// function to handle the request.  Wanted some regex matching for the 
// "hash" route, so decided to handle all of the routing in one place
// rather than rely on the net/http builtin HandleFunc.  
//
// This would be better handled by mux or other 3rd party routing library,
// but I couldn't find any regex-based routing built into the standard Go modules
func route(w http.ResponseWriter, r *http.Request) {

	var statsRoute = regexp.MustCompile(`^/stats/*$`) 
	var newHashRoute = regexp.MustCompile(`^/hash/*$`)
	var existingHashRoute = regexp.MustCompile(`^/hash/(?P<jobId>\d+)/*$`)

    switch {
    case statsRoute.MatchString(r.URL.Path):
    	// get server statistics
        getStats(w, r)
    case newHashRoute.MatchString(r.URL.Path):
    	// new password hash request
        createPasswordHash(w, r)
    case existingHashRoute.MatchString(r.URL.Path):
    	// read an existing password hash
    	res := existingHashRoute.FindStringSubmatch(r.URL.Path)
    	jobId, err := strconv.ParseUint(res[1], 10, 64)
    	if err != nil {
    		http.Error(w, "{\"msg\": \"Invalid job id\"}", http.StatusBadRequest)
    	} else {
    		readPasswordHash(w, r, jobId)
    	}
    	
    default:
        http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
    }
}

// shutdown blocks until all password hash requests in the work queue have
// been processed.
func shutdown() {
    fmt.Println("waiting for password requests to complete...")

    fmt.Println("shutting down workers...")


}

// main starts the service on port 8080, unless the user specifies an alternate port. 
func main() {

	// parse command line flags
	portPtr := flag.Int("p", 8080, "the server port number")
	queueSizePtr := flag.Int("q", 100, "size of the request queue")
	numWorkersPtr := flag.Int("w", 4, "number of password hashing workers")
	flag.Parse()

	// set the port
	port := fmt.Sprintf(":%d", *portPtr)
	// intialize the work queue
	PasswordHashWorkQueue = make(chan PasswordHashRequest, *queueSizePtr)
	// create a pool of workers to process requests on the work queue
	var workers = make([]*PasswordHashWorker, *numWorkersPtr)
	for w := 1; w <= *numWorkersPtr; w++ {
        workers[w-1] = NewPasswordHashWorker(w, PasswordHashWorkQueue, PasswordResultMap)
        workers[w-1].start()
    }

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
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGKILL)                               
	go func() {
		// graceful shutdown
		<-c
		// close the TCP channel to prevent additional requests
		l.Close()
		fmt.Println("waiting for password requests to complete...")
		var wait_iter = 0
		for (wait_iter < 1000 && len(PasswordHashWorkQueue) > 0) {
			wait_iter += 1
			time.Sleep(time.Second)
		}
    	fmt.Println("shutting down workers...")
    	for w := 1; w <= *numWorkersPtr; w++ {
	        workers[w-1].stop()
	    }
	    // wait a moment for the workers to shutdown
	    time.Sleep(time.Second * 10)
		os.Exit(0)                                                                                                                    
	}()    

	// set up the routes - specific uri's matched within the route function
	http.HandleFunc("/", route)

    // start the http server
    http.Serve(l, nil)

}
