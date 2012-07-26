
#include "webby.h"

#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <ctype.h>

#if defined(__PS3__)
#include "webby_ps3.h"
#elif defined(_WIN32)
#include "webby_win32.h"
#elif defined(__XBOX__)
#include "webby_xbox.h"
#else
#include "webby_unix.h"
#endif

#define WB_ALIGN_ARB(x, a) (((x) + ((a)-1)) & ~((a)-1))
#define WB_ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))

static const char continue_header[] = "HTTP/1.1 100 Continue\r\n\r\n";
static const size_t continue_header_len = sizeof(continue_header)-1;

#ifdef _MSC_VER
/* MSVC keeps complaining about constant conditionals inside the FD_SET() macro. */
#pragma warning(disable: 4127)
#endif

struct WebbyConnection;
struct WebbyRequest;

enum
{
  WB_ALIVE                  = 1 << 0,
  WB_FRESH_CONNECTION       = 1 << 1,
  WB_CLOSE_AFTER_RESPONSE   = 1 << 2,
  WB_CHUNKED_RESPONSE       = 1 << 3
};

enum
{
  WBC_REQUEST,
  WBC_SEND_CONTINUE,
  WBC_SERVE
};

struct WebbyBuffer
{
  int used;
  int max;
  char* data;
};

struct WebbyConnectionPrv
{
  struct WebbyConnection    public_data;

  int                       flags;
  webby_socket_t            socket;
  int                       state;    /* WBC_xxx */

  struct WebbyBuffer        header_buf;
  struct WebbyBuffer        io_buf;
  int                       header_body_left;
  int                       continue_data_left;
  int                       body_bytes_read;
  struct WebbyServer*       server;
};


struct WebbyServer
{
  struct WebbyServerConfig  config;
  int                       memory_size;
  webby_socket_t            socket;
  int                       connection_count;
  struct WebbyConnectionPrv connections[1];
};

static void dbg(struct WebbyServer *srv, const char *fmt, ...)
{
  char buffer[1024];
  va_list args;

  if (srv->config.flags & WEBBY_SERVER_LOG_DEBUG)
  {
    va_start(args, fmt);
    vsnprintf(buffer, sizeof buffer, fmt, args);
    va_end(args);

    buffer[(sizeof buffer)-1] = '\0';
    (*srv->config.log)(buffer);
  }
}

/* URL-decode input buffer into destination buffer.
 * 0-terminate the destination buffer. Return the length of decoded data.
 * form-url-encoded data differs from URI encoding in a way that it
 * uses '+' as character for space, see RFC 1866 section 8.2.1
 * http://ftp.ics.uci.edu/pub/ietf/html/rfc1866.txt
 *
 * This bit of code was taken from mongoose.
 */
static size_t url_decode(const char *src, size_t src_len, char *dst, size_t dst_len, int is_form_url_encoded)
{
  size_t i, j;
  int a, b;
#define HEXTOI(x) (isdigit(x) ? x - '0' : x - 'W')

  for (i = j = 0; i < src_len && j < dst_len - 1; i++, j++) {
    if (src[i] == '%' &&
      isxdigit(* (const unsigned char *) (src + i + 1)) &&
      isxdigit(* (const unsigned char *) (src + i + 2))) {
        a = tolower(* (const unsigned char *) (src + i + 1));
        b = tolower(* (const unsigned char *) (src + i + 2));
        dst[j] = (char) ((HEXTOI(a) << 4) | HEXTOI(b));
        i += 2;
    } else if (is_form_url_encoded && src[i] == '+') {
      dst[j] = ' ';
    } else {
      dst[j] = src[i];
    }
  }

#undef HEXTOI

  dst[j] = '\0'; /* Null-terminate the destination */

  return j;
}

/* Pulled from mongoose */
int WebbyFindQueryVar(const char *buf, const char *name, char *dst, int dst_len)
{
  const char *p, *e, *s;
  size_t name_len;
  int len;
  size_t buf_len = strlen(buf);

  name_len = strlen(name);
  e = buf + buf_len;
  len = -1;
  dst[0] = '\0';

  // buf is "var1=val1&var2=val2...". Find variable first
  for (p = buf; p != NULL && p + name_len < e; p++)
  {
    if ((p == buf || p[-1] == '&') && p[name_len] == '=' && 0 == strncasecmp(name, p, name_len))
    {
      // Point p to variable value
      p += name_len + 1;

      // Point s to the end of the value
      s = (const char *) memchr(p, '&', (size_t)(e - p));
      if (s == NULL) {
        s = e;
      }
      assert(s >= p);

      // Decode variable into destination buffer
      if ((size_t) (s - p) < dst_len)
      {
        len = (int) url_decode(p, (size_t)(s - p), dst, dst_len, 1);
      }
      break;
    }
  }

  return len;
}

const char *WebbyFindHeader(struct WebbyConnection *conn, const char *name)
{
  int i, count;
  for (i = 0, count = conn->request.header_count; i < count; ++i)
  {
    if (0 == strcasecmp(conn->request.headers[i].name, name))
    {
      return conn->request.headers[i].value;
    }
  }

  return NULL;
}


int
WebbyServerMemoryNeeded(const struct WebbyServerConfig *config)
{
  return
    WB_ALIGN_ARB(sizeof(struct WebbyServer), 16) +
    WB_ALIGN_ARB((config->connection_max - 1) * sizeof(struct WebbyConnection), 16) +
    config->connection_max * config->request_buffer_size +
    config->connection_max * config->io_buffer_size;
}

struct WebbyServer*
WebbyServerInit(struct WebbyServerConfig *config, void *memory, int memory_size)
{
  int i;
  struct WebbyServer *server = memory;
  char *buffer = memory;

  memset(buffer, 0, memory_size);

  server->config = *config;
  server->memory_size = memory_size;
  server->socket = WB_INVALID_SOCKET;

  buffer += WB_ALIGN_ARB(sizeof(struct WebbyServer) + sizeof(struct WebbyConnection) * (config->connection_max - 1), 16);

  for (i = 0; i < config->connection_max; ++i)
  {
    server->connections[i].server = server;

    server->connections[i].header_buf.data = buffer;
    buffer += config->request_buffer_size;

    server->connections[i].io_buf.data = buffer;
    buffer += config->io_buffer_size;
  }

  assert(buffer - (char*) memory <= memory_size);

  server->socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  dbg(server, "Server socket = %d", (int) server->socket);

  if (!wb_valid_socket(server->socket))
  {
    dbg(server, "failed to initialized server socket: %d", wb_socket_error());
    goto error;
  }

  {
    int on = 1;
    int off = 0;
    setsockopt(server->socket, SOL_SOCKET, SO_REUSEADDR, (const char*) &on, sizeof(int));
    setsockopt(server->socket, SOL_SOCKET, SO_LINGER, (const char*) &off, sizeof(int));
  }

  if (0 != wb_set_blocking(server->socket, 0))
  {
    goto error;
  }

  {
    struct sockaddr_in bind_addr;

    dbg(server, "binding to %s:%d", config->bind_address, config->listening_port);

    memset(&bind_addr, 0, sizeof bind_addr); // use 0.0.0.0
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = inet_addr(config->bind_address);
    bind_addr.sin_port = htons((unsigned short) config->listening_port);

    if (0 != bind(server->socket, (struct sockaddr*) &bind_addr, sizeof bind_addr))
    {
      dbg(server, "bind() failed: %d", wb_socket_error());
      goto error;
    }
  }

  if (0 != listen(server->socket, SOMAXCONN))
  {
    dbg(server, "listen() failed: %d", wb_socket_error());
    wb_close_socket(server->socket);
    goto error;
  }

  dbg(server, "server initialized");
  return server;

error:
  if (wb_valid_socket(server->socket))
  {
    wb_close_socket(server->socket);
  }
  return NULL;
}

void WebbyServerShutdown(struct WebbyServer *srv)
{
  int i;
  wb_close_socket(srv->socket);

  for (i = 0; i < srv->connection_count; ++i)
  {
    wb_close_socket(srv->connections[i].socket);
  }

  memset(srv, 0, srv->memory_size);
}

static int wb_config_incoming_socket(webby_socket_t socket)
{
  int err;

  if (0 != (err = wb_set_blocking(socket, 0)))
  {
    return err;
  }

  {
    int off = 0;
    setsockopt(socket, SOL_SOCKET, SO_LINGER, (const char*) &off, sizeof(int));
  }

  return 0;
}

static void reset_connection(struct WebbyServer *srv, struct WebbyConnectionPrv *conn)
{
  conn->header_buf.used       = 0;
  conn->header_buf.max        = srv->config.request_buffer_size;
  conn->io_buf.used           = 0;
  conn->io_buf.max            = srv->config.io_buffer_size;
  conn->flags                 = 0;
  conn->header_body_left      = 0;
  conn->continue_data_left    = 0;
  conn->body_bytes_read       = 0;
  conn->state                 = WBC_REQUEST;
  conn->public_data.user_data = NULL;
}

static int wb_on_incoming(struct WebbyServer *srv)
{
  int connection_index;
  char WB_ALIGN(8) client_addr[64];
  struct WebbyConnectionPrv* connection;
  webby_socklen_t client_addr_len = sizeof client_addr;
  webby_socket_t fd;

  /* Make sure we have space for a new connection */
  connection_index = srv->connection_count;

  if (connection_index == srv->config.connection_max)
  {
    dbg(srv, "out of connection slots");
    return 1;
  }

  /* Accept the incoming connection. */
  fd = accept(srv->socket, (struct sockaddr*) &client_addr[0], &client_addr_len);

  if (!wb_valid_socket(fd))
  {
    int err = wb_socket_error();
    if (!wb_is_blocking_error(err))
      dbg(srv, "accept() failed: %d", err);
    return 1;
  }

  connection = &srv->connections[connection_index];

  reset_connection(srv, connection);

  connection->flags       = WB_FRESH_CONNECTION;

  srv->connection_count = connection_index + 1;

  /* Configure socket */
  if (0 != wb_config_incoming_socket(fd))
  {
    wb_close_socket(fd);
    return 1;
  }

  /* OK, keep this connection */
  dbg(srv, "tagging connection %d as alive", connection_index);
  connection->flags |= WB_ALIVE;
  connection->socket = fd;
  return 0;
}

static int wb_peek_request_size(const char *buf, int len)
{
  int i;
  int max = len - 3;

  for (i = 0; i < max; ++i)
  {
    if ('\r' != buf[i]) 
      continue;

    if ('\n' != buf[i + 1])
      continue;

    if ('\r' != buf[i + 2])
      continue;

    if ('\n' != buf[i + 3])
      continue;

    /* OK; we have CRLFCRLF which indicates the end of the header section */
    return i + 4;
  }

  return -1;
}

static char* skipws(char *p)
{
  for (;;)
  {
    char ch = *p;
    if (' ' == ch || '\t' == ch)
      ++p;
    else
      break;
  }

  return p;
}

enum
{
  WB_TOK_SKIPWS = 1 << 0
};

static int tok_inplace(char *buf, const char* separator, char *tokens[], int max, int flags)
{
  int token_count = 0;
  char *b = buf;
  char *e = buf;
  int separator_len = (int) strlen(separator);

  while (token_count < max)
  {
    if (flags & WB_TOK_SKIPWS)
    {
      b = skipws(b);
    }

    if (NULL != (e = strstr(b, separator)))
    {
      int len = (int) (e - b);
      if (len > 0)
      {
        tokens[token_count++] = b;
      }
      *e = '\0';
      b = e + separator_len;
    }
    else
    {
      tokens[token_count++] = b;
      break;
    }
  }

  return token_count;
}

static void wb_close_client(struct WebbyServer *srv, struct WebbyConnectionPrv* connection)
{
  (void) srv;

  if (connection->flags & WB_ALIVE)
  {
    wb_close_socket(connection->socket);
    connection->socket = WB_INVALID_SOCKET;
  }

  connection->flags = 0;
}

static int wb_setup_request(struct WebbyServer *srv, struct WebbyConnectionPrv *connection, int request_size)
{
  char* lines[WEBBY_MAX_HEADERS + 2];
  int line_count;
  char* tok[16];
  char* query_params;
  int tok_count;

  int i;
  int header_count;

  char *buf = connection->header_buf.data;
  struct WebbyRequest *req = &connection->public_data.request;

  /* Null-terminate the request envelope by overwriting the last CRLF with 00LF */
  buf[request_size - 2] = '\0';

  /* Split header into lines */
  line_count = tok_inplace(buf, "\r\n", lines, WB_ARRAY_SIZE(lines), 0);

  header_count = line_count - 2;

  if (line_count < 1 || header_count > WB_ARRAY_SIZE(req->headers))
    return 1;

  /* Parse request line */
  tok_count = tok_inplace(lines[0], " ", tok, WB_ARRAY_SIZE(tok), 0);

  if (3 != tok_count)
    return 1;

  req->method = tok[0];
  req->uri = tok[1];
  req->http_version = tok[2];
  req->content_length = 0;

  /* See if there are any query parameters */
  if (NULL != (query_params = strchr(req->uri, '?')))
  {
    req->query_params = query_params + 1;
    *query_params = '\0';
  }
  else
    req->query_params = NULL;
  
  /* Decode the URI in place */
  {
    size_t uri_len = strlen(req->uri);
    url_decode(req->uri, uri_len, (char*) req->uri, uri_len + 1, /* url encoded: */ 1);
  }

  /* Parse headers */
  for (i = 0; i < header_count; ++i)
  {
    tok_count = tok_inplace(lines[i + 1], ":", tok, 2, WB_TOK_SKIPWS);

    if (tok_count != 2)
    {
      return 1;
    }

    req->headers[i].name = tok[0];
    req->headers[i].value = tok[1];

    if (0 == strcasecmp("content-length", tok[0]))
    {
      req->content_length = strtoul(tok[1], NULL, 10);
      dbg(srv, "request has body; content length is %d", req->content_length);
    }
    else if (0 == strcasecmp("transfer-encoding", tok[0]))
    {
      dbg(srv, "cowardly refusing to handle Transfer-Encoding: %s", tok[1]);
      return 1;
    }
  }

  req->header_count = header_count;

  return 0;
}

enum
{
  WB_FILL_OK,
  WB_FILL_ERROR,
  WB_FILL_FULL
};

/* Read as much as possible without blocking while there is buffer space. */
static int wb_fill_buffer(struct WebbyServer *srv, struct WebbyBuffer *buf, webby_socket_t socket)
{
  int err;
  int buf_left;

  for (;;)
  {
    buf_left = buf->max - buf->used;

    dbg(srv, "buffer space left = %d", buf_left);

    if (0 == buf_left)
    {
      return WB_FILL_FULL;
    }

    /* Read what we can into the current buffer space. */
    err = recv(socket, buf->data + buf->used, buf_left, 0);

    if (err < 0)
    {
      int sock_err = wb_socket_error();

      if (wb_is_blocking_error(sock_err))
      {
        return WB_FILL_OK;
      }
      else
      {
        /* Read error. Give up. */
        dbg(srv, "read error %d - connection dead", sock_err);
        return WB_FILL_ERROR;
      }
    }
    else if (err == 0)
    {
      /* The peer has closed the connection. */
      dbg(srv, "peer has closed the connection");
      return WB_FILL_ERROR;
    }
    else
    {
      buf->used += err;
    }
  }
}

static void wb_update_client(struct WebbyServer *srv, struct WebbyConnectionPrv* connection)
{
  /* This is no longer a fresh connection. Only read from it when select() says
   * so in the future. */
  connection->flags &= ~WB_FRESH_CONNECTION;

  for (;;)
  {
    switch (connection->state)
    {
      case WBC_REQUEST: {
        const char *expect_header;
        int result = wb_fill_buffer(srv, &connection->header_buf, connection->socket);
        int request_size;

        if (WB_FILL_ERROR == result)
        {
          connection->flags &= ~WB_ALIVE;
          return;
        }

        /* Scan to see if the buffer has a complete HTTP request header package. */ 
        request_size = wb_peek_request_size(connection->header_buf.data, connection->header_buf.used);

        dbg(srv, "peek request size: %d", request_size);
        if (request_size < 0)
        {
          /* Nothing yet. */
          if (connection->header_buf.max == connection->header_buf.used)
          {
            dbg(srv, "giving up as buffer is full");
            /* Give up, we can't fit the request in our buffer. */
            connection->flags &= ~WB_ALIVE;
          }
          return;
        }

        /* Set up request data. */
        if (0 != wb_setup_request(srv, connection, request_size))
        {
          dbg(srv, "failed to set up request");
          connection->flags &= ~WB_ALIVE;
          return;
        }

        /* Remember how much of the remaining buffer is body data. */
        connection->header_body_left = connection->header_buf.used - request_size;

        /* If the client expects a 100 Continue, send one now. */
        if (NULL != (expect_header = WebbyFindHeader(&connection->public_data, "Expect")))
        {
          if (0 == strcasecmp(expect_header, "100-continue"))
          {
            dbg(srv, "connection expects a 100 Continue header.. making him happy");
            connection->continue_data_left = (int) continue_header_len;
            connection->state = WBC_SEND_CONTINUE;
          }
          else
          {
            dbg(srv, "unrecognized Expected header %s", expect_header);
            connection->state = WBC_SERVE;
          }
        }
        else
        {
          connection->state = WBC_SERVE;
        }

        break;
      }

      case WBC_SEND_CONTINUE: {
        int left = connection->continue_data_left;
        int written = 0;

        written = send(connection->socket, continue_header + continue_header_len - left, left, 0);

        dbg(srv, "continue write: %d bytes", written);
        
        if (written < 0)
        {
          dbg(srv, "failed to write 100-continue header");
          connection->flags &= ~WB_ALIVE;
          return;
        }

        left -= written;
        connection->continue_data_left = left;

        if (0 == left)
        {
          connection->state = WBC_SERVE;
        }

        break;
      }

      case WBC_SERVE: {
        /* Clear I/O buffer for output */
        connection->io_buf.used = 0;

        /* Switch socket to blocking mode. */
        if (0 != wb_set_blocking(connection->socket, 1))
        {
          connection->flags &= ~WB_ALIVE;
          return;
        }

        if (0 != (*srv->config.dispatch)(&connection->public_data))
        {
          static const struct WebbyHeader headers[] =
          {
            { "Content-Type", "text/plain" },
          };
          WebbyBeginResponse(&connection->public_data, 404, -1, headers, WB_ARRAY_SIZE(headers));
          WebbyPrintf(&connection->public_data, "No handler for %s\r\n", connection->public_data.request.uri);
          WebbyEndResponse(&connection->public_data);
        }

        /* Back to non-blocking mode */
        if (0 != wb_set_blocking(connection->socket, 0))
        {
          connection->flags &= ~WB_ALIVE;
        }

        /* Ready for another request, unless we should close the connection. */
        if (connection->flags & WB_ALIVE)
        {
          if (connection->flags & WB_CLOSE_AFTER_RESPONSE)
          {
            connection->flags &= ~WB_ALIVE;
          }
          else
          {
            /* Reset buffer for next request. */
            reset_connection(srv, connection);
            connection->flags = WB_ALIVE;
            connection->state = WBC_REQUEST;
          }
        }
      }
    }
  }
}

void
WebbyServerUpdate(struct WebbyServer *srv)
{
  int i, count, err;
  webby_socket_t max_socket;
  fd_set read_fds, write_fds, except_fds;
  struct timeval timeout;

  /* Build set of sockets to check for events */
  FD_ZERO(&read_fds);
  FD_ZERO(&write_fds);
  FD_ZERO(&except_fds);

  max_socket = 0;

  /* Only accept incoming connections if we have space */
  if (srv->connection_count < srv->config.connection_max)
  {
    FD_SET(srv->socket, &read_fds);
    FD_SET(srv->socket, &except_fds);
    max_socket = srv->socket;
  }

  for (i = 0, count = srv->connection_count; i < count; ++i)
  {
    webby_socket_t socket = srv->connections[i].socket;
    FD_SET(socket, &read_fds);
    FD_SET(socket, &except_fds);

    if (srv->connections[i].state == WBC_SEND_CONTINUE)
      FD_SET(socket, &write_fds);

    if (socket > max_socket)
    {
      max_socket = socket;
    }
  }

  timeout.tv_sec = 0;
  timeout.tv_usec = 50;

  err = select((int) (max_socket + 1), &read_fds, &write_fds, &except_fds, &timeout);

  /* Handle incoming connections */
  if (FD_ISSET(srv->socket, &read_fds))
  {
    do
    {
      dbg(srv, "awake on incoming", i);
      err = wb_on_incoming(srv);
    } while (0 == err);
  }

  /* Handle incoming connection data */
  for (i = 0, count = srv->connection_count; i < count; ++i)
  {
    struct WebbyConnectionPrv *conn = &srv->connections[i];

    if (FD_ISSET(conn->socket, &read_fds) || FD_ISSET(conn->socket, &write_fds) || conn->flags & WB_FRESH_CONNECTION)
    {
      dbg(srv, "reading from connection %d", i);
      wb_update_client(srv, conn);
    }
  }

  /* Close stale connections & compact connection array. */
  for (i = 0; i < srv->connection_count; )
  {
    struct WebbyConnectionPrv *connection = &srv->connections[i];
    if (0 == (connection->flags & WB_ALIVE))
    {
      int remain = srv->connection_count - i - 1;
      dbg(srv, "closing connection %d", i);
      wb_close_client(srv, connection);
      memmove(&srv->connections[i], &srv->connections[i + 1], remain);
      --srv->connection_count;
    }
    else
    {
      ++i;
    }
  }
}

static int wb_flush(struct WebbyBuffer *buf, webby_socket_t socket)
{
  int err = 0;
  if (buf->used)
  {
    err = send(socket, buf->data, buf->used, 0);
    if (err != buf->used)
    {
      return 1;
    }
    buf->used = 0;
  }
  return 0;
}

static int wb_push(struct WebbyServer *srv, struct WebbyConnectionPrv *conn, const void *data_, int len)
{
  struct WebbyBuffer *buf = &conn->io_buf;
  const char* data = data_;

  if (conn->state != WBC_SERVE)
  {
    dbg(srv, "attempt to write in non-serve state");
    return 1;
  }

  if (0 == len)
  {
    return wb_flush(buf, conn->socket);
  }

  while (len > 0)
  {
    int buf_space = buf->max - buf->used;
    int copy_size = len < buf_space ? len : buf_space;
    memcpy(buf->data + buf->used, data, copy_size);
    buf->used += copy_size;

    data += copy_size;
    len -= copy_size;

    if (buf->used == buf->max)
    {
      if (0 != wb_flush(buf, conn->socket))
        return 1;

      if (len >= buf->max)
      {
        if (0 != wb_flush(buf, conn->socket))
          return 1;

        return send(conn->socket, data, len, 0);
      }
    }
  }

  return 0;
}

int WebbyPrintf(struct WebbyConnection* conn, const char* fmt, ...)
{
  int len;
  char buffer[1024];
  va_list args;

  va_start(args, fmt);
  len = vsnprintf(buffer, sizeof buffer, fmt, args);
  va_end(args);

  return WebbyWrite(conn, buffer, len);
}

static const short status_nums[] = {
   100, 101, 200, 201, 202, 203, 204, 205, 206, 300, 301, 302, 303, 304, 305,
   307, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413,
   414, 415, 416, 417, 500, 501, 502, 503, 504, 505
};

static const char* status_text[] = {
  "Continue", "Switching Protocols", "OK", "Created", "Accepted",
  "Non-Authoritative Information", "No Content", "Reset Content",
  "Partial Content", "Multiple Choices", "Moved Permanently", "Found",
  "See Other", "Not Modified", "Use Proxy", "Temporary Redirect", "Bad Request",
  "Unauthorized", "Payment Required", "Forbidden", "Not Found", "Method Not Allowed",
  "Not Acceptable", "Proxy Authentication Required", "Request Time-out", "Conflict",
  "Gone", "Length Required", "Precondition Failed", "Request Entity Too Large",
  "Request-URI Too Large", "Unsupported Media Type", "Requested range not satisfiable",
  "Expectation Failed", "Internal Server Error", "Not Implemented", "Bad Gateway",
  "Service Unavailable", "Gateway Time-out", "HTTP Version not supported"
};

static const char *wb_status_text(int status_code)
{
  int i;
  for (i = 0; i < WB_ARRAY_SIZE(status_nums); ++i)
  {
    if (status_nums[i] == status_code)
      return status_text[i];
  }
  return "Unknown";
}

int WebbyBeginResponse(struct WebbyConnection *conn_pub, int status_code, int content_length, const struct WebbyHeader headers[], int header_count)
{
  int i = 0;
  struct WebbyConnectionPrv *conn = (struct WebbyConnectionPrv *) conn_pub;

  if (conn->body_bytes_read < conn->public_data.request.content_length)
  {
    int body_left = conn->public_data.request.content_length - conn->body_bytes_read;
    dbg(conn->server, "warning: %d bytes of body data left to read; throwing it away!", body_left);

    while (body_left > 0)
    {
      char buffer[1024];
      int read_size = body_left > sizeof buffer ? sizeof buffer : body_left;
      if (0 != WebbyRead(conn_pub, buffer, read_size))
        return 1;

      body_left -= read_size;
    }
  }

  WebbyPrintf(conn_pub, "HTTP/1.1 %d %s\r\n", status_code, wb_status_text(status_code));

  if (content_length >= 0)
  {
    WebbyPrintf(conn_pub, "Content-Length: %d\r\n", content_length);
  }
  else
  {
    WebbyPrintf(conn_pub, "Transfer-Encoding: chunked\r\n");
  }

  WebbyPrintf(conn_pub, "Server: Webby\r\n");

  for (i = 0; i < header_count; ++i)
  {
    if (0 == strcasecmp(headers[i].name, "Connection"))
    {
      if (0 == strcasecmp(headers[i].value, "close"))
      {
        conn->flags |= WB_CLOSE_AFTER_RESPONSE;
      }
    }
    WebbyPrintf(conn_pub, "%s: %s\r\n", headers[i].name, headers[i].value);
  }

  if (0 == (conn->flags & WB_CLOSE_AFTER_RESPONSE))
  {
    /* See if the client wants us to close the connection. */
    const char* connection_header = WebbyFindHeader(conn_pub, "Connection");
    if (connection_header && 0 == strcasecmp("close", connection_header))
    {
      conn->flags |= WB_CLOSE_AFTER_RESPONSE;
      WebbyPrintf(conn_pub, "Connection: close\r\n");
    }
  }

  WebbyPrintf(conn_pub, "\r\n");

  if (content_length < 0)
  {
    conn->flags |= WB_CHUNKED_RESPONSE;
  }

  return 0;
}

int WebbyRead(struct WebbyConnection *conn, void *ptr_, int len)
{
  struct WebbyConnectionPrv* conn_prv = (struct WebbyConnectionPrv*) conn;
  char *ptr = (char*) ptr_;

  if (conn_prv->header_body_left > 0)
  {
    int left = conn_prv->header_body_left;
    int offset = conn_prv->header_buf.used - left;
    int read_size = len > left ? left : len;

    memcpy(ptr, conn_prv->header_buf.data + offset, read_size);

    ptr += read_size;
    len -= read_size;
    conn_prv->header_body_left -= read_size;
    conn_prv->body_bytes_read += read_size;
  }

  while (len > 0)
  {
    int err = recv(conn_prv->socket, ptr, len, 0);

    if (err < 0)
    {
      conn_prv->flags &= ~WB_ALIVE;
      return err;
    }

    len -= err;
    ptr += err;
    conn_prv->body_bytes_read += err;
  }

  return 0;
}

int WebbyWrite(struct WebbyConnection *conn, const void *ptr, int len)
{
  struct WebbyConnectionPrv *conn_priv = (struct WebbyConnectionPrv *) conn;

  if (conn_priv->flags & WB_CHUNKED_RESPONSE)
  {
    char chunk_header[128];
    int header_len = snprintf(chunk_header, sizeof chunk_header, "%x\r\n", len);
    wb_push(conn_priv->server, conn_priv, chunk_header, header_len);
    wb_push(conn_priv->server, conn_priv, ptr, len);
    return wb_push(conn_priv->server, conn_priv, "\r\n", 2);
  }
  else
  {
    return wb_push(conn_priv->server, conn_priv, ptr, len);
  }
}

void WebbyEndResponse(struct WebbyConnection *conn)
{
  struct WebbyConnectionPrv *conn_priv = (struct WebbyConnectionPrv *) conn;

  if (conn_priv->flags & WB_CHUNKED_RESPONSE)
  {
    /* Write final chunk */
    wb_push(conn_priv->server, conn_priv, "0\r\n\r\n", 5);

    conn_priv->flags &= ~WB_CHUNKED_RESPONSE;
  }

  /* Flush buffers */
  wb_push(conn_priv->server, conn_priv, "", 0);
}
