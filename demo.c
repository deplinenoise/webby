#include "webby.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <winsock2.h>
#endif

#ifdef __APPLE__
#include <unistd.h>
#endif

static int quit = 0;

static void test_log(const char* text)
{
  printf("[debug] %s\n", text);
}

static int test_dispatch(struct WebbyConnection *connection)
{
  if (0 == strcmp("/foo", connection->request.uri))
  {
    WebbyBeginResponse(connection, 200, 14, NULL, 0);
    WebbyWrite(connection, "Hello, world!\n", 14);
    WebbyEndResponse(connection);
    return 0;
  }
  else if (0 == strcmp("/bar", connection->request.uri))
  {
    WebbyBeginResponse(connection, 200, -1, NULL, 0);
    WebbyWrite(connection, "Hello, world!\n", 14);
    WebbyWrite(connection, "Hello, world?\n", 14);
    WebbyEndResponse(connection);
    return 0;
  }
  else if (0 == strcmp(connection->request.uri, "/quit"))
  {
    WebbyBeginResponse(connection, 200, -1, NULL, 0);
    WebbyPrintf(connection, "Goodbye, cruel world\n");
    WebbyEndResponse(connection);
    quit = 1;
    return 0;
  }
  else
    return 1;
}

int main(int argc, char *argv[])
{
  int i;
  void *memory;
  int memory_size;
  struct WebbyServer *server;
  struct WebbyServerConfig config;

#if defined(_WIN32)
  {
    WORD wsa_version = MAKEWORD(2, 2);
    WSADATA wsa_data;
    if (0 != WSAStartup( wsa_version, &wsa_data ))
    {
      fprintf(stderr, "WSAStartup failed\n");
      return 1;
    }
  }
#endif

  config.bind_address = "127.0.0.1";
  config.listening_port = 8081;
  config.flags = 0;
  config.connection_max = 4;
  config.request_buffer_size = 2048;
  config.io_buffer_size = 8192;
  config.dispatch = &test_dispatch;
  config.log = &test_log;

  for (i = 1; i < argc; )
  {
    if (0 == strcmp(argv[i], "-p"))
    {
      config.listening_port = atoi(argv[i + 1]);
      i += 2;
    }
    else if (0 == strcmp(argv[i], "-b"))
    {
      config.bind_address = argv[i + 1];
      i += 2;
    }
    else if (0 == strcmp(argv[i], "-d"))
    {
      config.flags = WEBBY_SERVER_LOG_DEBUG;
      i += 1;
    }
    else
      ++i;
  }

  memory_size = WebbyServerMemoryNeeded(&config);
  memory = malloc(memory_size);
  server = WebbyServerInit(&config, memory, memory_size);

  if (!server)
  {
    fprintf(stderr, "failed to init server\n");
    return 1;
  }

  while (!quit)
  {
    WebbyServerUpdate(server);
#if defined(__APPLE__)
    usleep(30 * 1000);
#elif defined(_WIN32)
    Sleep(30);
#endif
  }

  WebbyServerShutdown(server);
  free(memory);

#if defined(_WIN32)
  WSACleanup();
#endif

  return 0;
}
