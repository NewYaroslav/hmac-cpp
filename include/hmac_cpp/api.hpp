#ifndef HMAC_CPP_API_HPP
#define HMAC_CPP_API_HPP

#if defined(_WIN32) || defined(__CYGWIN__)
  #if defined(HMAC_CPP_STATIC)
    #define HMAC_CPP_API
  #elif defined(HMAC_CPP_BUILD)
    #define HMAC_CPP_API __declspec(dllexport)
  #else
    #define HMAC_CPP_API __declspec(dllimport)
  #endif
#elif defined(__GNUC__) && __GNUC__ >= 4
  #define HMAC_CPP_API __attribute__((visibility("default")))
#else
  #define HMAC_CPP_API
#endif

#endif // HMAC_CPP_API_HPP
