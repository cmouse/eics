#include "eics.hh"

static const wchar_t *logLevels[] = {
  L"ERROR",
  L"WARN",
  L"INFO",
  L"DEBUG"
};

eics::Log::~Log() { 
     char tbuf[128];
     time_t t; 
     struct tm tm; 
     t = time((time_t*)NULL);
     localtime_r(&t, &tm);
     strftime(tbuf, 128, "%Y-%m-%d %H:%M:%S+%Z", &tm);
     std::wcerr << tbuf << L" [" << logLevels[logLevel] << L"]: " << buf.str() << std::endl; 
};
