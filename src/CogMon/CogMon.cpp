// CogMon.cpp.
//
// TODO:
// 0- Create a 'exit now' event with luid as name.
// 1- Create a single instance event object
// 2- Process json result from /inf request
// 3- global structure to track processes launched
// 4- if in /reg the exe exists but not running, launch it
// 5- if exception, copy log to dropbox.
//

#include <SDKDDKVer.h>

#include <winsock2.h>
#include <iphlpapi.h>
#include <Wincrypt.h>
#include <WinTrust.h>
#include <SoftPub.h>

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
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")

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
  0, 1, 2, 8, 16, 32, 64, 128, 256
};

const unsigned long kWait_Update_mins = 5;


class FilePath {
private:
  std::wstring path_;
  friend class File;

public:
  explicit FilePath(const wchar_t* path)
    : path_(path) {
  }

  explicit FilePath(const std::wstring& path)
    : path_(path) {
  }

  FilePath Parent() const {
    auto pos = path_.find_last_of(L'\\');
    if (pos == std::string::npos)
      return FilePath();
    return FilePath(path_.substr(0, pos));
  }

  FilePath Append(const std::wstring& name) const {
    std::wstring full(path_);
    if (!path_.empty())
      full.append(1, L'\\');
    full.append(name);
    return FilePath(full);
  }

  const wchar_t* Raw() const { return path_.c_str(); }

private:
  FilePath() {}
};

FilePath GetExePath() {
  wchar_t* pp = nullptr;
  _get_wpgmptr(&pp);
  return FilePath(pp).Parent();
}

class Logger {
public:
  static const int sys_logger   = 0;
  static const int sys_http     = 1;
  static const int sys_updater  = 2;
  static const int sys_prog     = 3;
  static const int sys_crypto   = 4;

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

  Logger(const FilePath& path, uint64_t luid)
      : log_(path.Raw()), luid_(luid) {
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

uint64_t GetMacAddress() {
  unsigned long buflen = 1024*8;
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
    return *reinterpret_cast<uint64_t*>(&adapter->PhysicalAddress[0]);
  }

  // If we are not connected to a network, we use a 24 bit random number.
  return ::GetTickCount() & 0xffffff;
}

std::wstring GetCertificateDescription(const CERT_CONTEXT* cert_ctx) {   
  DWORD dwStrType = CERT_X500_NAME_STR;
  DWORD dwCount = CertGetNameString(cert_ctx, CERT_NAME_RDN_TYPE, 0, &dwStrType, NULL, 0);
  if (!dwCount){
    return std::wstring();
  }
  std::unique_ptr<wchar_t> subjectRDN(new wchar_t[0, dwCount]);
  CertGetNameString(cert_ctx, CERT_NAME_RDN_TYPE, 0, &dwStrType, subjectRDN.get(), dwCount);
  return std::wstring(subjectRDN.get());
}

bool VerifyBinaryCert(Logger& logger, const FilePath& bin_path, std::vector<char>& cert_hash) {
  WINTRUST_FILE_INFO wt_file_info = {sizeof(wt_file_info)};
  WINTRUST_DATA wt_data = {sizeof(wt_data)};

  wt_file_info.pcwszFilePath = bin_path.Raw();
  wt_data.dwUIChoice          = WTD_UI_NONE;
  wt_data.fdwRevocationChecks = WTD_REVOKE_NONE;
  wt_data.dwUnionChoice       = WTD_CHOICE_FILE;
  wt_data.pFile               = &wt_file_info;
  wt_data.dwStateAction       = WTD_STATEACTION_VERIFY;

  GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  DWORD result = ::WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &wt_data);

  if (result != ERROR_SUCCESS) {
    logger(log_level::LOG_ERROR, Logger::sys_crypto) 
        << "WinVerifyTrust failed, result: " << std::hex << result;
    return false;
  }

  // We don't trust the  root certs of a regular windows installation. If we did
  // then we could end up executing any exe from a system32 folder send over to us.

  CRYPT_PROVIDER_DATA *provdata = ::WTHelperProvDataFromStateData(wt_data.hWVTStateData);
  if (!provdata) {
    logger(log_level::LOG_ERROR, Logger::sys_crypto) << "CRYPT_PROVIDER_DATA is null";
    return false;
  }
  
  CRYPT_PROVIDER_SGNR *provsigner = ::WTHelperGetProvSignerFromChain(provdata, 0, FALSE, 0);
  if (!provsigner) {
    logger(log_level::LOG_ERROR, Logger::sys_crypto) << "CRYPT_PROVIDER_SGNR is null";
    return false;
  }

  CRYPT_PROVIDER_CERT* provcert = WTHelperGetProvCertFromChain(provsigner, 0);
  if (!provcert) {
    logger(log_level::LOG_ERROR, Logger::sys_crypto) << "CRYPT_PROVIDER_CERT is null";
    return false;
  }

  std::wstring name = GetCertificateDescription(provcert->pCert);
  bool trusted = (name == L"CN=cogsoft2") && provcert->fSelfSigned && provcert->fTrustedRoot;

  wt_data.dwUIChoice = WTD_UI_NONE;
  wt_data.dwStateAction = WTD_STATEACTION_CLOSE;
  WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &wt_data);

  return trusted;
}

struct UpdateInfo {
  enum Action {
    Unknown,
    Download,
    Execute,
    Verify
  };

  Action action;
  uri update_url;
  string_t name;
  string_t component;
  string_t path;
  int32_t version;
  string_t options;
};

struct NodeInfo {
  uint64_t mac_addr;
  uint64_t loc_uuid;
  string_t server;
  FilePath base_path;
  HANDLE main_thread;
};

struct ApcContext {
  enum Event {
    HeartBeat,
    ProcessExit,
    SelfExit
  };

  Logger* logger;
  NodeInfo node;
  UpdateInfo info;
  Event event;
  DWORD exit_code;

  ApcContext(Logger* logger, const NodeInfo& node, const UpdateInfo& info)
      : logger(logger), node(node), info(info) {
  }

  ApcContext(Logger* logger, const NodeInfo& node) 
      : logger(logger), node(node) {
  }
};

void __stdcall ApcCallBack(ULONG_PTR context) {
  std::unique_ptr<ApcContext> ctx (reinterpret_cast<ApcContext*>(context));

  Logger& logger = *ctx->logger;
  logger(log_level::LOG_INFO, Logger::sys_prog)
      << "processing apc event : " << ctx->event
      << " for: " << ctx->info.component;

  if (ctx->event == ApcContext::SelfExit) {
    logger(log_level::LOG_INFO, Logger::sys_prog) << "self exit by signal";
    g_isProcessTerminating = 1;
    return;
  }

  std::wostringstream oss1, oss2, oss3;
  oss1 << std::hex << ctx->node.mac_addr;
  oss2 << std::hex << ctx->node.loc_uuid;

  oss3 << ctx->info.component << L':'
       << ctx->info.version << L':' << std::hex << ctx->exit_code;

  auto url = uri_builder(U("/inf")).append_query(U("mac"), oss1.str())
                                   .append_query(U("uid"), oss2.str())
                                   .append_query(U("tpc"), "p_end")
                                   .append_query(U("nod"), oss3.str())
                                   .to_string();

  http_client client(ctx->node.server);
  auto rq = client.request(methods::GET, url);
  auto status = rq.wait();
  auto response = rq.get();

  if (status_codes::OK != response.status_code()) {
    logger(log_level::LOG_ERROR, Logger::sys_updater)
        << "http 'inf' GET failed, code: " << response.status_code()
        << " reason: " << response.reason_phrase();
    return;
  }

}

bool CheckForUpdates(Logger& logger, const NodeInfo& node, UpdateInfo& update_info) {

  std::wostringstream oss1, oss2;
  oss1 << std::hex << node.mac_addr;
  oss2 << std::hex << node.loc_uuid;

  auto url = uri_builder(U("/reg")).append_query(U("mac"), oss1.str())
                                   .append_query(U("uid"), oss2.str())
                                   .append_query(U("tpc"), "ucheck1")
                                   .to_string();

  http_client client(node.server);
  auto rq = client.request(methods::GET, url);
  auto status = rq.wait();
  auto response = rq.get();
  if (status_codes::OK != response.status_code()) {
    logger(log_level::LOG_ERROR, Logger::sys_updater)
        << "http 'req' GET failed, code: " << response.status_code()
        << " reason: " << response.reason_phrase();
    return false;
  }

  string_t download_url;
  int required = 5;

  response.extract_json().then([&logger, &download_url, &required, &update_info](json::value dic) {
    for (auto iter = dic.cbegin(); iter != dic.cend(); ++iter) {
      auto key = iter->first.as_string();
	    if (key == U("Update")) {
        download_url = iter->second.as_string();
        --required;
      } else if (key == U("Component")) {
        update_info.component = iter->second.as_string();
        --required;
      } else if (key == U("Version")) {
        update_info.version = iter->second.as_integer();
        --required;
      } else if (key == U("Name")) {
        update_info.name = iter->second.as_string();
        --required;
      } else if (key == U("Action")) {
        auto action = iter->second.as_string();
        if (action == U("download"))
          update_info.action = UpdateInfo::Download;
        else if (action == U("execute"))
          update_info.action = UpdateInfo::Execute;
        else if (action == U("verify"))
          update_info.action = UpdateInfo::Verify;
        else
          update_info.action = UpdateInfo::Unknown;
        --required;
      } else {
        // Unknown field.
        logger(log_level::LOG_WARNING, Logger::sys_updater) << "json unknown field: " << key;
      }
    }
  }).wait();

  if (!uri::validate(download_url)) {
    logger(log_level::LOG_ERROR, Logger::sys_updater) << "invalid url : " << download_url;
    return false;
  }

  if (required || update_info.name.empty() || update_info.component.empty()) {
    logger(log_level::LOG_ERROR, Logger::sys_updater) << "missing json fields :" << required;
    return false;
  }

  if (update_info.version < 0) {
    logger(log_level::LOG_ERROR, Logger::sys_updater) << "negative version :" << update_info.version;
    return false;
  }

  std::wostringstream oss;
  oss << update_info.version;
  FilePath component_dir = node.base_path.Append(update_info.component).Append(oss.str());
  update_info.path = component_dir.Append(update_info.name).Raw();

  WIN32_FIND_DATA finddata = {0};
  HANDLE h = ::FindFirstFile(update_info.path.c_str(), &finddata);
  if (h != INVALID_HANDLE_VALUE) {
    logger(log_level::LOG_INFO, Logger::sys_prog)
        << "component is already here.: " << component_dir.Raw();
    return false;
  }
  
  if (!::CreateDirectory(component_dir.Parent().Raw(), NULL)) {
    if (::GetLastError() != ERROR_ALREADY_EXISTS) {
      logger(log_level::LOG_FATAL, Logger::sys_prog)
          << "failed to create component root directory: " << component_dir.Raw();
      return false;
    }
  }

  if (!::CreateDirectory(component_dir.Raw(), NULL)) {
    if (::GetLastError() != ERROR_ALREADY_EXISTS) {
      logger(log_level::LOG_FATAL, Logger::sys_prog)
          << "failed to create component version directory: " << component_dir.Raw();
      return false;
    }
  }

  update_info.update_url = uri(download_url);
  return true;
}

bool DownloadUpdate(Logger& logger, const NodeInfo& node, const UpdateInfo& update_info) {
  std::wostringstream oss;
  oss << std::hex << ::GetTickCount64();
  string_t download_path = node.base_path.Append(L"downloads").Append(oss.str()).Raw();

  logger(log_level::LOG_INFO, Logger::sys_updater)
      << "downloading: " << update_info.update_url.to_string()
      << " to :" << download_path;

  http_client client(update_info.update_url.authority());
  string_t resource = update_info.update_url.resource().to_string();
  size_t downloaded = 0;

  {
    auto t1 = client.request(methods::GET, resource);
    auto c1 = t1.then([&logger](http_response& response) {
      bool sc = response.status_code() == status_codes::OK;
      return pplx::create_task([sc]() { return sc; });
    });

    auto t2 = file_buffer<uint8_t>::open(download_path,
                                         std::ios::out |
                                         std::ios::binary |
                                         std::ios::trunc);

    auto c2 = t2.then([](streambuf<uint8_t>& filebuf) {
      return pplx::create_task([]() { return true; });
    });

    (c1 && c2).then([&downloaded, t1, t2](std::vector<bool> result) {
      if (result[0] && result[1]) {
        downloaded = t1.get().body().read_to_end(t2.get()).get();
        t2.get().close().wait();
      }
    }).wait();

    if (!downloaded) {
      logger(log_level::LOG_ERROR, Logger::sys_updater)
          << "download failed, server response was: " << t1.get().reason_phrase();
      return false;
    }
  }

  logger(log_level::LOG_INFO, Logger::sys_updater) << "downloaded OK, size: " << downloaded;

  std::vector<char> hash;
  if (!VerifyBinaryCert(logger, FilePath(download_path), hash)) {
    logger(log_level::LOG_ERROR, Logger::sys_updater) << "install aborted, authenticode failure";
    return false;
  }

  if (!::MoveFile(download_path.c_str(), update_info.path.c_str())) {
    auto error = ::GetLastError();
    logger(log_level::LOG_ERROR, Logger::sys_updater) << "move file failed, error: " << error;
    return false;
  }

  logger(log_level::LOG_INFO, Logger::sys_updater) << "file installed, ready for action";
  return true;
}

bool DoAction(Logger& logger, const NodeInfo& node, const UpdateInfo& info) {
  if (info.action == UpdateInfo::Unknown) {
    logger(log_level::LOG_WARNING, Logger::sys_updater) << "unknown action";
    return false;
  }

  if (info.action == UpdateInfo::Execute) {
    DWORD cflags = 0;
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};

    std::wostringstream oss;
    oss << "creator:cogmon." << std::hex << node.loc_uuid;
    wchar_t* cmdline = &oss.str()[0];

    if (!::CreateProcess(info.path.c_str(), cmdline, NULL, NULL, FALSE, cflags, NULL, NULL, &si, &pi)) {
      auto error = ::GetLastError();
      logger(log_level::LOG_ERROR, Logger::sys_updater) << "process exec failed, error: " << error;
      return false;
    }
    ::CloseHandle(pi.hThread);
    logger(log_level::LOG_INFO, Logger::sys_updater) << "process started, pid: " << pi.dwProcessId;

    HANDLE process = pi.hProcess;
    HANDLE thread = node.main_thread;
    auto context = new ApcContext(&logger, node, info);

    pplx::create_task([process, thread, context]() {
      ::WaitForSingleObject(process, INFINITE);
      // The process exited. We'll continue processing the event once we
      // get to sleepex in the main thread.
      context->event = ApcContext::ProcessExit;
      ::GetExitCodeProcess(process, &context->exit_code);
      ::CloseHandle(process);
      ::QueueUserAPC(&ApcCallBack, thread, ULONG_PTR(context));
      return true;
    });

  }
  return true;
}

uint64_t GetLocalUniqueId() {
  LUID luid = {0};
  ::AllocateLocallyUniqueId(&luid);
  ULARGE_INTEGER li = {luid.LowPart, luid.HighPart};
  return li.QuadPart;
}

void CreateLifetimeMonitor(Logger& logger, const NodeInfo& node) {

  std::wostringstream oss;
  oss << "cog_" << std::hex << node.loc_uuid;
  HANDLE event = ::CreateEventW(NULL, TRUE, FALSE, oss.str().c_str());
  HANDLE thread = node.main_thread;
  auto context = new ApcContext(&logger, node);

  pplx::create_task([context, event, thread]() {
      ::WaitForSingleObject(event, INFINITE);
      context->event = ApcContext::SelfExit;
      // Our lifetime handle got signaled. Exit when in the main loop.      
      ::QueueUserAPC(&ApcCallBack, thread, ULONG_PTR(context));
      return true;
  });
}

int __stdcall wWinMain(HINSTANCE instance, HINSTANCE, wchar_t* cmdline, int n_show) {

  uint64_t mac_addr = GetMacAddress();
  uint64_t loc_uuid = GetLocalUniqueId();
  
  // This binary should be located at y\x\component\version\cogmon.exe and the base
  // path should be x. On debug builds it is at CogMon\out\x64\Debug so the base
  // path is |CogMon\out|. We need two directories to operate, |logs| and |downloads|.

  FilePath base_path = GetExePath().Parent().Parent();
  Logger logger(base_path.Append(U("logs")), loc_uuid);

  logger(log_level::LOG_INFO, Logger::sys_prog) 
      << "starting updater url: " << kServer
      << " mac address: " << std::hex << mac_addr;

  if (!mac_addr)
    return 1;

  if(!::CreateDirectory(base_path.Append(U("downloads")).Raw(), NULL)) {
    if (::GetLastError() != ERROR_ALREADY_EXISTS) {
      logger(log_level::LOG_FATAL, Logger::sys_prog)
          << "failed to create downloads directory , error: " << ::GetLastError();
      return 1;
    }
  }

  HANDLE thread = ::OpenThread(THREAD_ALL_ACCESS, FALSE, ::GetCurrentThreadId());
  const NodeInfo node = {mac_addr, loc_uuid, kServer, base_path, thread};

  CreateLifetimeMonitor(logger, node);

  unsigned long loops = 0;

  while(true) {
    try {
      unsigned long mins = kWaits_NoUpdate_mins[loops % _countof(kWaits_NoUpdate_mins)];
      ::SleepEx(mins * 60 * 1000, TRUE);
      ++loops;

      if (g_isProcessTerminating)
        break;

      UpdateInfo update_info;
      if (!CheckForUpdates(logger, node, update_info))
        continue;
      
      if (!DownloadUpdate(logger, node, update_info))
        continue;

      loops = 0;
      DoAction(logger, node, update_info);

    } catch(http_exception e) {
      logger(log_level::LOG_ERROR, Logger::sys_http) << "http exception: " << e.what();
    } catch(json::json_exception e) {
      logger(log_level::LOG_ERROR, Logger::sys_http) << "json exception: " << e.what();
    } catch(std::exception e) {
      logger(log_level::LOG_ERROR, Logger::sys_http) << "std exception: " << e.what();
    }

  }

  // required by casablanca framework.
  g_isProcessTerminating = 1;
  return 0;
}
