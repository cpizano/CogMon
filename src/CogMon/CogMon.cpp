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

typedef std::basic_ostringstream<string_t> OstringStream;

// casablanca needs this, there it goes in dllmain.
volatile long g_isProcessTerminating = 0;

//const auto kServer = U("http://cogsrv.appspot.com/");
const auto kServer = U("http://localhost:8080/");

const unsigned long kWaits_NoUpdate_mins[] = {
  0, 2, 8, 16, 32, 64, 128, 256
};

const unsigned long kWait_Update_mins = 5;

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
      if ((level_ == log_level::LOG_ERROR) || (level_ == log_level::LOG_FATAL)) {
        if (::IsDebuggerPresent()) __debugbreak();
      }
    }

    template <typename T>
    LogNode& operator<<(const T& t) {
      oss_ << t;
      return *this;
    }

  private:
    
    LocalFileLog& log_;
    std::wostringstream oss_;

    const log_level level_;
    const int code_;
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
  for ( ; adapter; adapter = adapter->Next) {
    if (adapter->OperStatus != IfOperStatusUp)
      continue;
    if ((adapter->IfType != IF_TYPE_ETHERNET_CSMACD) && (adapter->IfType != IF_TYPE_IEEE80211))
      continue;
    if (!adapter->PhysicalAddressLength)
      continue;
    mac = *reinterpret_cast<uint64_t*>(&adapter->PhysicalAddress[0]);
    return true;
  }

  // $$$ remove this.
  mac = 1;
  return false;
}

struct UpdateInfo {
  uri update_url;
  int32_t version;
  string_t path;
  string_t options;
};

bool CheckForUpdates(Logger& logger, const string_t& server,
                     uint64_t client_id, UpdateInfo& update_info) {

  std::wostringstream oss1, oss2;
  oss1 << std::hex << client_id;
  oss2 << update_info.version;

  auto url = uri_builder(U("/reg")).append_query(U("id"), oss1.str())
                                   .append_query(U("tp"), "ucheck")
                                   .append_query(U("ve"), oss2.str())
                                   .to_string();

  http_client client(server);
  auto rq = client.request(methods::GET, url);
  auto status = rq.wait();
  auto response = rq.get();
  if (status_codes::OK != response.status_code()) {
    logger(log_level::LOG_ERROR, Logger::sys_updater)
        << "code: " << response.status_code()
        << "reason: " << response.reason_phrase();
    return false;
  }

  update_info.version = -1;
  string_t download_url;
  int required = 3;

  response.extract_json().then([&download_url, &required, &update_info](json::value dic) {
    for (auto iter = dic.cbegin(); iter != dic.cend(); ++iter) {
      auto key = iter->first.as_string();
	    if (key == U("Update")) {
        download_url = iter->second.as_string();
        --required;
        continue;
      }
      else if (key == U("Version")) {
        update_info.version = iter->second.as_integer();
        --required;
        continue;
      }
      else if (key == U("Path")) {
        update_info.path = iter->second.as_string();
        --required;
        continue;
      }
    }
  }).wait();

  if (!uri::validate(download_url)) {
    logger(log_level::LOG_ERROR, Logger::sys_updater) << "invalid url : " << download_url;
    return false;
  }

  if (required) {
    logger(log_level::LOG_ERROR, Logger::sys_updater) << "missing json fields :" << required;
    return false;
  }
  
  update_info.update_url = uri(download_url);
  return true;
}

size_t DownloadUpdate(Logger& logger, const UpdateInfo& update_info) {
  logger(log_level::LOG_INFO, Logger::sys_updater)
      << "downloading: " << update_info.update_url.to_string()
      << " to :" << update_info.path;

  http_client client(update_info.update_url);
  string_t resource = update_info.update_url.resource().to_string();

  auto t1 = client.request(methods::GET, resource);
  auto c1 = t1.then([&logger](http_response& response) {
    bool sc = response.status_code() == status_codes::OK;
    return pplx::create_task([sc]() { return sc; });
  });

  auto t2 = file_buffer<uint8_t>::open(U("update_001.jpg"), std::ios::out);
  auto c2 = t2.then([](streambuf<uint8_t>& filebuf) {
    return pplx::create_task([]() { return true; });
  });

  size_t downloaded = 0;
  (c1 && c2).then([&downloaded, t1, t2](std::vector<bool> result) {
    if (result[0] && result[1]) {
      t1.get().body().read_to_end(t2.get()).then([t2, &downloaded](size_t size) {
        downloaded = size;
        t2.get().close();
      });
    }
  }).wait();

  if (!downloaded) {
    logger(log_level::LOG_ERROR, Logger::sys_updater)
        << "download failed, server response was: " << t1.get().reason_phrase();

  } else {
    logger(log_level::LOG_INFO, Logger::sys_updater) << "downloaded OK, size: " << downloaded;
  }
  return downloaded;
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

  UpdateInfo update_info;
  update_info.version = -1;
  unsigned long loops = 0;

  while(true) {
    try {

      unsigned long mins = kWaits_NoUpdate_mins[loops % _countof(kWaits_NoUpdate_mins)];
      ::Sleep(mins * 60 * 1000);
      ++loops;

      uri url;
      if (!CheckForUpdates(logger, kServer, mac_addr, update_info)) {
        continue;
      }

      if (DownloadUpdate(logger, update_info)) {
        logger(log_level::LOG_INFO, Logger::sys_updater) << "download succesful";
        ::Sleep(kWait_Update_mins * 60 * 1000);
      }

      loops = 0;

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
