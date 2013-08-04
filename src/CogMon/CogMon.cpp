// CogMon.cpp.

#include <SDKDDKVer.h>

#include <winsock2.h>
#include <iphlpapi.h>

#include "CogMon.h"

#include <stdlib.h>
#include <malloc.h>
#include <sstream>

#include <cpprest/http_client.h>
#include <cpprest/filestream.h>
#include <cpprest/filelog.h>
#include <cpprest/json.h>

#pragma comment(lib, "casablanca.lib")
#pragma comment(lib, "IPHLPAPI.lib")


using namespace concurrency::streams;
using namespace utility;
using namespace web;
using namespace web::http;
using namespace web::http::client;
using namespace utility::experimental::logging;

// casablanca needs this, there it goes in dllmain.
volatile long g_isProcessTerminating = 0;

const auto kCogId = U("BA234588134");
//const auto kServer = U("http://cogsrv.appspot.com/");
const auto kServer = U("http://localhost:8080/");

const unsigned long kWaits_mins[] = {
  0, 2, 8, 16, 32, 64, 128, 256
};

class Logger {
public:
  static const int sys_logger   = 0;
  static const int sys_http     = 1;
  static const int sys_updater  = 2;

  class LogNode {
  public:
    LogNode(LocalFileLog& log, log_level level, int code, uint64_t luid) 
        : log_(log), level_(level), code_(code) {
      oss_ << std::hex << luid << std::dec << L" ";
    }

    ~LogNode() {
      log_.post(level_, code_, oss_.str());
    }

    template <typename T>
    LogNode& operator<<(const T& t) {
      oss_ << t;
      return *this;
    }

  private:
    
    LocalFileLog& log_;
    std::wostringstream oss_;
    log_level level_;
    int code_;
  };

  Logger(const string_t& folder, uint64_t luid)
      : log_(folder), luid_(luid) {
    LogNode(log_, log_level::LOG_INFO, sys_logger, luid_) 
        << "<< starting log session >> pid:" << ::GetCurrentProcessId()
        << " uptime:" <<::GetTickCount64() / 1000;
  }

  ~Logger() {
    LogNode(log_, log_level::LOG_INFO, sys_logger, luid_)
        << "<< log session end >>";
    log_.flush();
  }

  LogNode operator()(log_level level, int sys_code) {
    return LogNode(log_, level, sys_code, luid_);
  }

private:
  LocalFileLog log_;
  uint64_t luid_;
};

bool GetMacAddress(uint64_t& mac) {
  unsigned long buflen = 1024*5;
  std::unique_ptr<IP_ADAPTER_ADDRESSES> addrs(reinterpret_cast<IP_ADAPTER_ADDRESSES*>(new char[buflen]));
  unsigned long flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_FRIENDLY_NAME;
  unsigned long rc = GetAdaptersAddresses(AF_INET, flags, NULL, addrs.get(), &buflen);
  if (rc != NO_ERROR)
    return false;
  IP_ADAPTER_ADDRESSES* adapter = addrs.get();
  while (adapter) {
    if (adapter->OperStatus != IfOperStatusUp)
      continue;
    if ((adapter->IfType != IF_TYPE_ETHERNET_CSMACD) && (adapter->IfType != IF_TYPE_IEEE80211))
      continue;
    if (!adapter->PhysicalAddressLength)
      continue;
    mac = *reinterpret_cast<uint64_t*>(&adapter->PhysicalAddress[0]);
    return true;
  }

  return false;
}


bool CheckForUpdates(const string_t& server, uri& update_url, int32_t& version) {
  http_client client(server);
  auto url = uri_builder(U("/reg")).append_query(U("id"), kCogId).append_query(U("tp"), "ucheck").to_string();
  auto rq = client.request(methods::GET, url);
  auto status = rq.wait();
  auto response = rq.get();
  if (status_codes::OK != response.status_code()) {
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

uint64_t GetLocalUniqueId() {
  LUID luid = {0};
  ::AllocateLocallyUniqueId(&luid);
  ULARGE_INTEGER li = {luid.LowPart, luid.HighPart};
  return li.QuadPart;
}

int __stdcall wWinMain(HINSTANCE instance, HINSTANCE, wchar_t* cmdline, int n_show) {

  uint64_t uuid = GetLocalUniqueId();
  Logger logger(L"cogmon_logs", uuid);

  uint64_t mac_addr = 0;
  GetMacAddress(mac_addr);

  logger(log_level::LOG_INFO, Logger::sys_updater) 
      << "starting updater url: " << kServer
      << " mac address: " << std::hex << mac_addr;

  if (!mac_addr)
    return 1;

  int32_t current_version = -1;
  int32_t version;
  unsigned long loops = 0;

  while(true) {
    try {

      unsigned long mins = kWaits_mins[loops % _countof(kWaits_mins)];
      ::Sleep(mins * 60 * 1000);
      ++loops;

      uri url;
      if (!CheckForUpdates(kServer, url, version)) {
        continue;
      }

      if (version <= current_version) {
        logger(log_level::LOG_INFO, Logger::sys_updater) << "version is: " << version;
        continue;
      }

      loops = 0;
      DownloadUpdate(url);
      ::Sleep(5 * 60 * 1000);

    } catch(http_exception e) {
      logger(log_level::LOG_ERROR, Logger::sys_http) << "http exception: " << e.what();
    } catch(json::json_exception e) {
      logger(log_level::LOG_ERROR, Logger::sys_http) << "json exception: " << e.what();
    }

  }

  g_isProcessTerminating = 1;

#if 0
  MSG msg = {0};
	while (::GetMessageW(&msg, NULL, 0, 0)) {
    ::TranslateMessage(&msg);
    ::DispatchMessageW(&msg);
	}

	return (int) msg.wParam;
#endif
}
