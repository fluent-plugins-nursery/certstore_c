#include <ruby.h>
#include <ruby/encoding.h>

#ifdef __GNUC__
# include <w32api.h>
# define MINIMUM_WINDOWS_VERSION WindowsVista
#else /* __GNUC__ */
# define MINIMUM_WINDOWS_VERSION 0x0600 /* Vista */
#endif /* __GNUC__ */

#ifdef _WIN32_WINNT
#  undef WIN32_WINNT
#endif /* WIN32_WINNT */
#define _WIN32_WINNT MINIMUM_WINDOWS_VERSION

#include <certstore.h>

VALUE rb_mCertstore;
VALUE rb_cCertLoader;
VALUE rb_eCertstoreError;

static void certstore_loader_free(void *certstore);

static const rb_data_type_t rb_win_certstore_loader_type = {
  "winevt/certstore_loader", {
    0, certstore_loader_free, 0,
  }, NULL, NULL,
  RUBY_TYPED_FREE_IMMEDIATELY
};

struct CertstoreLoader {
  HCERTSTORE hStore;
};

static void
certstore_loader_free(void *ptr)
{
  struct CertstoreLoader *loader = (struct CertstoreLoader *)ptr;
  CertCloseStore(loader->hStore, 0);

  xfree(ptr);
}

static VALUE
rb_win_certstore_loader_alloc(VALUE klass)
{
  VALUE obj;
  struct CertstoreLoader *loader;
  obj = TypedData_Make_Struct(klass,
                              struct CertstoreLoader,
                              &rb_win_certstore_loader_type,
                              loader);
  return obj;
}

static VALUE
rb_win_certstore_loader_initialize(VALUE self, VALUE store_name)
{
  VALUE vStoreName;
  struct CertstoreLoader *loader;
  DWORD len;

  Check_Type(store_name, T_STRING);

  // channel : To wide char
  len = MultiByteToWideChar(CP_UTF8, 0, RSTRING_PTR(store_name), RSTRING_LEN(store_name), NULL, 0);
  PWSTR winStoreName = ALLOCV_N(WCHAR, vStoreName, len+1);
  MultiByteToWideChar(CP_UTF8, 0, RSTRING_PTR(store_name), RSTRING_LEN(store_name), winStoreName, len);
  winStoreName[len] = L'\0';

  TypedData_Get_Struct(self, struct CertstoreLoader, &rb_win_certstore_loader_type, loader);

  loader->hStore = CertOpenSystemStoreW(0, winStoreName);

  return Qnil;
}

char*
wstr_to_mbstr(UINT cp, const WCHAR *wstr, int clen)
{
    char *ptr;
    int len = WideCharToMultiByte(cp, 0, wstr, clen, NULL, 0, NULL, NULL);
    if (!(ptr = xmalloc(len))) return NULL;
    WideCharToMultiByte(cp, 0, wstr, clen, ptr, len, NULL, NULL);

    return ptr;
}

static VALUE
certificate_context_to_string(PCCERT_CONTEXT pContext)
{
  WCHAR wszString[4096];
  DWORD cchString;
  CHAR *utf8str;
  CHAR certificate[4150];
  CHAR *certHeader = "-----BEGIN CERTIFICATE-----\n";
  CHAR *certFooter = "\n-----END CERTIFICATE-----";

  cchString = ARRAYSIZE(wszString);
  CryptBinaryToStringW(pContext->pbCertEncoded, pContext->cbCertEncoded,
                       CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, wszString, &cchString);

  utf8str = wstr_to_mbstr(CP_UTF8, wszString, -1);
  sprintf(certificate, "%s%s%s", certHeader, utf8str, certFooter);
  return rb_utf8_str_new_cstr(certificate);
}

static VALUE
rb_win_certstore_loader_each_pem(VALUE self)
{
  PCCERT_CONTEXT pContext = NULL;
  struct CertstoreLoader *loader;

  RETURN_ENUMERATOR(self, 0, 0);

  TypedData_Get_Struct(self, struct CertstoreLoader, &rb_win_certstore_loader_type, loader);

  while ((pContext = CertEnumCertificatesInStore(loader->hStore, pContext)) != NULL) {
    VALUE rb_certificate = certificate_context_to_string(pContext);
    rb_yield(rb_certificate);
  }

  CertFreeCertificateContext(pContext);

  return Qnil;
}

void
Init_certstore(void)
{
  rb_mCertstore = rb_define_module("Certstore");
  rb_cCertLoader = rb_define_class_under(rb_mCertstore, "Loader", rb_cObject);
  rb_eCertstoreError = rb_define_class_under(rb_cCertLoader, "CertstoreError", rb_eStandardError);

  rb_define_alloc_func(rb_cCertLoader, rb_win_certstore_loader_alloc);
  rb_define_method(rb_cCertLoader, "initialize", rb_win_certstore_loader_initialize, 1);
  rb_define_method(rb_cCertLoader, "each_pem", rb_win_certstore_loader_each_pem, 0);
}
