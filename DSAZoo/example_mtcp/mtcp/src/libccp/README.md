# libccp [![Build Status](https://travis-ci.org/ccp-project/libccp.svg?branch=master)](https://travis-ci.org/ccp-project/libccp)

Libccp is an implementation of the core functionality necsesary for a datapath
to communicate with a CCP process. The datapath is responsible for providing 
a few callback functions for modifying state internal to the datapath
(e.g. congestion window or packet pacing rate) and a few utility functions
and libccp handles everything else. The instructions below detail all of the
steps necessary to make a datapath CCP compatible.  

## Implementation

### 0 | Include ccp.h in all relevant files

In C source files:

```C
#include "libccp/ccp.h"
```

In C++ source files:

```C++
extern "C" {
#include "libccp/ccp.h"
}
```


### 1 | Initialization Global (ccp_init and ccp_free)

In an initialize / register function called once (not per connection),
we need to provide pointers to 6 callback/utility functions for 
libccp to invoke (we'll come back to the implementation of them later).
All of the functions must be implemented or libccp will throw an error.
There is a single optional `impl` field, which is a `void*` that can be 
used to retain a reference to global datapath state, which will be passed as a
parameter to each of the callback functions. For example, in the mtcp datapath, 
`impl` is a pointer to the global mtcp context structure, which holds the unix
sockets necessary for communicating with the CCP. The `send_msg` function is a
callback invoked by the ccp that must have access to these sockets.

(Note in this example e.g. `_set_cwnd` is the datapath's implementation of the
`set_cwnd` function.)

```C
struct ccp_datapath dp = {
	.set_cwnd = &_set_cwnd,
        .set_rate_abs = &_set_rate_abs,
        .set_rate_rel = &_set_rate_rel,
        .now = &_now,
        .after_usecs = &_after_usecs
        .send_msg = &_send_msg,
        .impl = // pointer to anything
};

ok = ccp_init(&dp);
if (ok < 0) {
	return -1;
}
```

Be sure to call `ccp_free` in a destructor as well:

```C
ccp_free();
```


### 2 | Initialize Connection (ccp_connection_start and ccp_connection_free)

When a new connection is created, the datapath must call `ccp_connection_start`,
This function again takes a `void*` which can be used to store datapath-specific
per-connection state (e.g. the linux kernel datapath uses this field to store a
reference to the corresponding `struct sock`) and returns a pointer to a 
`struct ccp_connection`. This should be stored somewhere for later access. It
will be necessary for accessing the `impl` and the deconstructor at the end.

On connection start:

```C
struct sock sk;
...
conn = ccp_connection_start((void *) sk);
if (conn == NULL) {
  // connection failed
} else {
  // connection successful, has index dp->index
}
// save reference to conn somewhere

```

When connection ends:

```C
// need reference to conn from above

if (conn != NULL) {
	ccp_connection_free(conn->index);
} else {
	// already freed
}
```

Given a reference to the `struct ccp_connection`, the `impl` field can be
accessed and casted like so (e.g. unboxing a `struct sock *`)

```C
struct sock *sk;
*sk = (struct sock *) ccp_get_impl(dp);
```


### 3 | Implement control functions

Now it's time to implement the functions from Step 1. The function signatures
and relevant details can all be found in `libccp/ccp.h`. Check out the
`ccp-kernel` or `ccp-mtcp` repositories for specific examples of how these
functions might be implemented.

Make sure the names of these functions match what you provided to `ccp_init`.


### 4 | Implement measurement 

On each ACK received, you must set all of the fields in `conn->prims`
accordingly with the measurements for the ACK,
and then call `ccp_invoke(conn)`. Libccp will use this to update its internal
state and occasionally send this to the ccp. As the datapath, you don't need to
be concerned with when this happens, as libccp handles all of this using the
`send_msg` function from (3). 

```C
struct ccp_connection *conn;
// ... get access to conn for this connection
struct ccp_primitives *mmt = &conn->prims

mmt->bytes_acked =      // ...
mmt->bytes_misordered = // ... 
...

ccp_invoke(conn);
conn->prims.was_timeout = false;
```

`prims.was_timeout` is by default set to false. Whenver the datapath suspects
there has been a drop, this field should be set to true. Just be sure to set it
back to false again after calling `ccp_invoke` (as above) to make sure that the
same signal is not handled twice.
Again libccp is responsible for when it communicates this information to the ccp.



## Putting it all together

Now you should be ready to build everything. The following is for userspace datapaths; for kernel datapaths, see https://github.mit.edu/nebula/ccp-kernel.


### 0 | Build libccp

Simply run `make` in the top level of this repository.
This will produce the shared library `libccp.so`. You can leave it here, 
or move it to a more standard location (e.g. `/usr/lib`). Either way, be
sure to note the path, it will be used as `LIBCCP` in the following step.

**Important Note: If you intend to link libccp with C++ code, you must build
libccp with a C++ compiler (e.g. `g++`) rather than `gcc`. Change the first
line of the Makefile to `CC=g++` and recompile.**

### 1 | Link libccp

Add the following to your project Makefile. This will link against libccp and
ensure the compiler knows where to find the necessary header files.
* be sure to set /path/to/libccp appropriately
* if LIBS and INC are already defined, change = to +=
```
LIBCCP = /path/to/libccp
LIBS = -L$(LIBCCP) -lccp
INC = -I$(LIBCCP)
```

If LIBS and INC are not already included, be sure to add them to your compile
comands, e.g...
```
file.o : file.c
    $(CC) -c file.c $(INC)
exe : file.o
	$(CC) file.o $(INC) $(LIBS) -o exe
```


### 2 | Build your application

Just run `make`. 

Before running your application, you need to ensure that the path to libccp is
included in the `LD_LIBRARY_PATH` environment variable so that your application
knows where to find the library at run time.

For example, if its stored at `/home/ubuntu/libs/libccp.so`, you can append 
as follows
```
LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/ubuntu/libs
```
