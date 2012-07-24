#ifndef WEBBY_H
#define WEBBY_H

/*
   Webby - A tiny little web server for game debugging.
*/

/* Server initialization flags */
enum
{
  WEBBY_SERVER_LOG_DEBUG    = 1 << 0,
};

/* Hard limits */
enum
{
  WEBBY_MAX_HEADERS         = 64
};

struct WebbyServer;

/* A HTTP header */
struct WebbyHeader
{
  const char *name;
  const char *value;
};

/* A HTTP request. */
struct WebbyRequest
{
  /* The method of the request, e.g. "GET", "POST" and so on */
  const char *method;
  /* The URI that was used. */
  const char *uri;
  /* The HTTP version that used. */
  const char *http_version;
  /* The number of bytes of request body that are available via WebbyRead() */
  int content_length;
  /* The number of headers */
  int header_count;
  /* Request headers */
  struct WebbyHeader headers[WEBBY_MAX_HEADERS];
};

/* Connection state, as published to the serving callback. */
struct WebbyConnection
{
  /* The request being served. Read-only. */
  struct WebbyRequest request;
  
  /* User data. Read-write. Webby doesn't care about this. */
  void *user_data;
};

/* Configuration data required for starting a server. */
struct WebbyServerConfig
{
  /* The bind address. Must be a textual IP address. */
  const char *bind_address;

  /* The port to listen to. */
  int listening_port;

  /* Flags. Right now WEBBY_SERVER_LOG_DEBUG is the only valid flag. */
  int flags;

  /* Maximum number of simultaneous connections. */
  int connection_max;

  /* The size of the request buffer. This must be big enough to contain all
   * headers and the request line sent by the client. 2-4k is a good size for
   * this buffer. */
  int request_buffer_size;

  /* The size of the I/O buffer, used when writing the reponse. 4k is a good
   * choice for this buffer.*/
  int io_buffer_size;

  /* Optional callback function that receives debug log text (without
   * newlines). */
  void (*log)(const char *msg);

  /* Request dispatcher function. This function is called when the request
   * structure is ready.
   *
   * If you decide to handle the request, call WebbyBeginResponse(),
   * WebbyWrite() and WebbyEndResponse() and then return 0. Otherwise, return a
   * non-zero value to have Webby send back a 404 response.
   */
  int (*dispatch)(struct WebbyConnection *connection);
};

/* Returns the amount of memory needed for the specified config. */
int
WebbyServerMemoryNeeded(const struct WebbyServerConfig *config);

/* Initialize a server in the specified memory space. Size must be big enough,
 * as determined by WebbyServerMemoryNeeded(). The memory block must be aligned
 * to at least 8 bytes.
 */
struct WebbyServer*
WebbyServerInit(struct WebbyServerConfig *config, void *memory, int memory_size);

/* Update the server. Call frequently (at least once per frame). */
void
WebbyServerUpdate(struct WebbyServer *srv);

/* Shutdown the server and close all sockets. */
void
WebbyServerShutdown(struct WebbyServer *srv);

/*
 * Begin a response.
 *
 * status_code - The HTTP status code to send. Normally 200
 * content_length - size in bytes you intend to write, or -1 for chunked encoding
 * headers - Array of HTTP headers to transmit (can be NULL if header_count ==0)
 * header_count - Number of headers in the array.
 *
 * Returns zero on success, non-zero on error.
 */
int
WebbyBeginResponse(
    struct WebbyConnection *conn,
    int status_code,
    int content_length,
    const struct WebbyHeader headers[],
    int header_count);

/*
 * Finish a response.
 *
 * When you're done writing the response body, call this function. It makes
 * sure that chunked encoding is terminated correctly and that the connection
 * is set up for reuse.
 */
void
WebbyEndResponse(struct WebbyConnection *conn);

/*
 * Read data from the request body. Only read what the client has provided (via
 * the content_length) parameter, or you will end up blocking forever.
 */
int WebbyRead(struct WebbyConnection *conn, void *ptr, int len);

/*
 * Write response data to the connection. If you're not using chunked encoding,
 * be careful not to send more than the specified content length. You can call
 * this function multiple times as long as the total number of bytes matches up
 * with the content length.
 */
int WebbyWrite(struct WebbyConnection *conn, const void *ptr, int len);

/*
 * Convenience function to do formatted printing to a response. Only useful
 * when chunked encoding is being used.
 */
int WebbyPrintf(struct WebbyConnection *conn, const char *fmt, ...);

/*
 * Convenience function to find a header in a request. Returns the value of the
 * specified header, or NULL if it was not present.
 */
const char *WebbyFindHeader(struct WebbyConnection *conn, const char *name);

#endif
