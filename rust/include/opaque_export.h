#pragma once

#if defined(_WIN32)
#  if defined(OPAQUE_BUILD_DLL)
#    define OPAQUE_API __declspec(dllexport)
#  elif defined(OPAQUE_USE_DLL)
#    define OPAQUE_API __declspec(dllimport)
#  else
#    define OPAQUE_API
#  endif
#else
#  define OPAQUE_API __attribute__((visibility("default")))
#endif
