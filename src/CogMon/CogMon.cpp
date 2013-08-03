// CogMon.cpp.

#define WIN32_LEAN_AND_MEAN
#include <SDKDDKVer.h>
#include <windows.h>

#include <stdlib.h>
#include <malloc.h>

#include "CogMon.h"


#include <cpprest/http_client.h>
#include <cpprest/filestream.h>
#include <cpprest/json.h>

#pragma comment(lib, "casablanca.lib")

using namespace concurrency::streams;
using namespace utility;
using namespace web;
using namespace web::http;
using namespace web::http::client;

const auto kCogId = U("BA234588134");
//const auto kServer = U("http://cogsrv.appspot.com/");
const auto kServer = U("http://localhost:8080/");

bool CheckForUpdates(const string_t& server, uri& update_url, int32_t& version) {
  http_client client(server);
  auto url = uri_builder(U("/reg")).append_query(U("id"), kCogId).append_query(U("tp"), "ucheck").to_string();
  auto rq = client.request(methods::GET, url);
  auto status = rq.wait();
  auto response = rq.get();
  if (200 != response.status_code()) {
    return false;
  }

  version = -1;
  string_t download;
  response.extract_json().then([&download, &version](json::value dic) {
    for (auto iter = dic.cbegin(); iter != dic.cend(); ++iter) {
      auto key = iter->first.as_string();
	    if (key == U("update")) {
        download = iter->second.as_string();
        continue;
      }
      if (key == U("version")) {
        version = iter->second.as_integer();
        continue;
      }
    }
  }).wait();

  if (!uri::validate(download))
    return false;
  
  update_url = uri(download);
  return true;
}

bool DownloadUpdate(const uri& url) {
  return false;
}

int __stdcall wWinMain(HINSTANCE instance, HINSTANCE, wchar_t* cmdline, int n_show) {

  const unsigned long waits_mins[] = {
    0, 1, 5, 10, 20, 60, 200, 250
  };

  int32_t current_version = -1;
  int32_t version;
  unsigned long loops = 0;

  while(true) {
    try {
      ++loops;
      uri url;
      if (!CheckForUpdates(kServer, url, version)) {
        ::Sleep(waits_mins[loops % _countof(waits_mins)] * 60 * 1000);
        continue;
      }

      if (version <= current_version) {
        continue;
      }

      loops = 0;
      DownloadUpdate(url);
      ::Sleep(5 * 60 * 1000);

    } catch(http_exception e) {
      // log something
      ::Beep(440, 30);
    } catch(json::json_exception e) {
      // log something
      ::Beep(330, 40);
    }

  }

#if 0
  MSG msg = {0};
	while (::GetMessageW(&msg, NULL, 0, 0)) {
    ::TranslateMessage(&msg);
    ::DispatchMessageW(&msg);
	}

	return (int) msg.wParam;
#endif
}
