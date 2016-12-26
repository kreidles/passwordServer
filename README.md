The passwordServer package
=========================

The passwordServer is an http server which asynchronously encrypts passwords via a REST API.

The server is written in Go, and assumes you have installed the standard libraries from [https://golang.org/](https://golang.org/).

# Installation

* Clone the repo from Github.com

```
git clone https://github.com/kreidles/passwordServer.git
```

* Set your GOPATH variable

```
export GOPATH=go_work_dir
```

* Compile

```
go install ./passwordServer/
```

# Usage

* Start the server

```
$GOPATH/bin/passwordServer [-p=<port>] [-q=<queue_size>] [-w=<num_workers>]
```

* Command-line flags are optional and include
   * -p=<port>, runs the server  on the specified port
   * -q=<queue_size>, controls the buffer size of the internal work queue
   * -w=<num_workers>, controls the number of worker threads to process password hash requests

* Stop the server by hitting Ctrl-C.  The server will wait until any remaining password requests are processed, and then shutdown the worker threads.  No additional requests are accepted during shutdown.


# API

The passwordServer has three REST endpoints:

* A POST to /hash accepts a form-encoded password value, queues a password hash job, and returns the job id.  
* A GET to /hash/:jobId returns the base64 encoded password hash for the corresponding POST request.  A 404 Not Found is returned if the job does not exist or is not done processing
* A GET to /stats returns a JSON data structure showing the total hash requests since server start and the average time of a hash request in milliseconds.
    * The request time is calculated as the elapsed time between the job being added to the work queue and completion of password processing.

# Internal structure

The passwordServer uses a work queue to handle asynchronous requests.  When a password hash request is received at the /hash endpoint, the server

* Adds a new password hash job to the work queue
* A worker from the worker pool retrieves the job.  The worker then
   * Waits 5 seconds
   * Generates the SHA512 hash of the password
   * Stores the hash in a thread-safe hashmap for later retrieval
   
Results can then be retrieved via a GET call to /hash/:jobId


# Example usage

Start the server on http://localhost:8080

```
$GOPATH/bin/passwordServer
```

Request password encryption via a POST to /hash

```
curl -data "password=angryMonkey" http://localhost:8080/hash
```

Returns the job id

```
1
```

After waiting a few seconds, request the job result

```
curl http://localhost:8080/hash/1
```

Returns the password hash

```
ZEHhWB65gUlzdVwtDQArEyx+KVLzp/aTaRaPlBzYRIFj6vjFdqEb0Q5B8zVKCZ0vKbZPZklJz0Fd7s
u2A+gf7Q==
```

To view the server statistics

```
curl http://localhost:8080/stats
```

Returns

```
{“total”: 1, “average”: 5001}
```

