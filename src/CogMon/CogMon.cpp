// CogMon.cpp.

#define WIN32_LEAN_AND_MEAN
#include <SDKDDKVer.h>
#include <windows.h>

#include <stdlib.h>
#include <malloc.h>

#include "CogMon.h"


#include <cpprest/http_client.h>
#include <cpprest/filestream.h>

#pragma comment(lib, "casablanca.lib")

using namespace utility;
using namespace web::http;
using namespace web::http::client;
using namespace concurrency::streams;


int __stdcall wWinMain(HINSTANCE instance, HINSTANCE, wchar_t* cmdline, int n_show) {

  const string_t searchTerm(L"cats");

  http_client client(U("http://www.bing.com/"));
  auto url = uri_builder(U("/search")).append_query(U("q"), searchTerm).to_string();
  auto rq = client.request(methods::GET, url);
  auto status = rq.wait();
  auto response = rq.get();
  if (200 != response.status_code()) {
    return 1;
  }
  auto body = response.body();
  response.extract_string().then([](string_t str) {
    auto str2 = str;
  }).wait();

  MSG msg = {0};
	while (::GetMessageW(&msg, NULL, 0, 0)) {
    ::TranslateMessage(&msg);
    ::DispatchMessageW(&msg);
	}

	return (int) msg.wParam;
}
