#ifndef _CERTSTORE_H_
#define _CERTSTORE_H_

#include <ruby.h>
#include <ruby/encoding.h>

#ifdef __GNUC__
# include <w32api.h>
# define MINIMUM_WINDOWS_VERSION WindowsVista
#else /* __GNUC__ */
# define MINIMUM_WINDOWS_VERSION 0x0600 /* Vista */
#endif /* __GNUC__ */

#ifdef _WIN32_WINNT
#  undef _WIN32_WINNT
#endif /* WIN32_WINNT */
#define _WIN32_WINNT MINIMUM_WINDOWS_VERSION

#define CERT_THUMBPRINT_STR_LENGTH 40
#define CERT_THUMBPRINT_SIZE (160 / 8)

#include <Wincrypt.h>

#endif // _WINEVT_H
