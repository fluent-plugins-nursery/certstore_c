#include <certstore.h>

VALUE rb_mCertstore;
VALUE rb_cCertLoader;
VALUE rb_eCertLoaderError;

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
  if (loader->hStore)
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
  WCHAR *wszString;
  DWORD cchString;
  CHAR *utf8str;
  CHAR *certificate;
  CHAR *certHeader = "-----BEGIN CERTIFICATE-----\n";
  CHAR *certFooter = "\n-----END CERTIFICATE-----";
  CHAR errBuf[256];
  DWORD errCode;

  if (!CryptBinaryToStringW(pContext->pbCertEncoded, pContext->cbCertEncoded,
                            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &cchString)) {
    rb_raise(rb_eCertLoaderError, "cannot obtain certificate string length.");
  }

  wszString = malloc(sizeof(WCHAR) * cchString);
  CryptBinaryToStringW(pContext->pbCertEncoded, pContext->cbCertEncoded,
                       CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, wszString, &cchString);

  utf8str = wstr_to_mbstr(CP_UTF8, wszString, -1);
  // malloc sizeof CHAR * ((base64 cert content + header + footer) length).
  certificate = malloc(sizeof(CHAR) * (strlen(utf8str) + strlen(certHeader) + strlen(certFooter)));
  sprintf(certificate, "%s%s%s", certHeader, utf8str, certFooter);

  if (ERROR_SUCCESS != GetLastError() && CRYPT_E_NOT_FOUND != GetLastError()) {
    sprintf(errBuf, "ErrorCode(%d)", GetLastError());

    goto error;
  }

  VALUE rb_pem = rb_utf8_str_new_cstr(certificate);
  free(wszString);
  free(certificate);

  return rb_pem;

error:
  rb_raise(rb_eCertLoaderError, errBuf);
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

static VALUE
rb_win_certstore_loader_close_hstore(VALUE self)
{
  struct CertstoreLoader *loader;

  TypedData_Get_Struct(self, struct CertstoreLoader, &rb_win_certstore_loader_type, loader);

  /* What should we dispose here? */

  return Qnil;
}

static VALUE
rb_win_certstore_loader_each(VALUE self)
{
  PCCERT_CONTEXT pContext = NULL;
  struct CertstoreLoader *loader;

  RETURN_ENUMERATOR(self, 0, 0);

  TypedData_Get_Struct(self, struct CertstoreLoader, &rb_win_certstore_loader_type, loader);

  rb_ensure(rb_win_certstore_loader_each_pem, self, rb_win_certstore_loader_close_hstore, self);

  return Qnil;
}

static VALUE
rb_win_certstore_loader_find_certificate(VALUE self, VALUE rb_thumbprint)
{
  VALUE vThumbprint;
  PCCERT_CONTEXT pContext = NULL;
  struct CertstoreLoader *loader;
  DWORD len;
  CHAR errBuf[256];

  Check_Type(rb_thumbprint, T_STRING);

  TypedData_Get_Struct(self, struct CertstoreLoader, &rb_win_certstore_loader_type, loader);

  // channel : To wide char
  len = MultiByteToWideChar(CP_UTF8, 0, RSTRING_PTR(rb_thumbprint), RSTRING_LEN(rb_thumbprint), NULL, 0);
  WCHAR *winThumbprint = ALLOCV_N(WCHAR, vThumbprint, len+1);
  MultiByteToWideChar(CP_UTF8, 0, RSTRING_PTR(rb_thumbprint), RSTRING_LEN(rb_thumbprint), winThumbprint, len);
  winThumbprint[len] = L'\0';

  BYTE pbThumb[CERT_THUMBPRINT_SIZE];
  CRYPT_HASH_BLOB blob;
  blob.cbData = CERT_THUMBPRINT_SIZE;
  blob.pbData = pbThumb;
  CryptStringToBinaryW(winThumbprint, CERT_THUMBPRINT_STR_LENGTH, CRYPT_STRING_HEX, pbThumb,
                       &blob.cbData, NULL, NULL);

  pContext = CertFindCertificateInStore(
              loader->hStore,
              X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
              0,
              CERT_FIND_HASH,
              &blob,
              pContext);

  if (!pContext)
    goto error;

  VALUE rb_certificate = certificate_context_to_string(pContext);
  CertFreeCertificateContext(pContext);

  return rb_certificate;

error:

  CertFreeCertificateContext(pContext);

  sprintf(errBuf, "Cannot find certificates with thumbprint(%S)", winThumbprint);
  rb_raise(rb_eCertLoaderError, errBuf);
}

void
Init_certstore(void)
{
  rb_mCertstore = rb_define_module("Certstore");
  rb_cCertLoader = rb_define_class_under(rb_mCertstore, "Loader", rb_cObject);
  rb_eCertLoaderError = rb_define_class_under(rb_cCertLoader, "LoaderError", rb_eStandardError);

  rb_define_alloc_func(rb_cCertLoader, rb_win_certstore_loader_alloc);
  rb_define_method(rb_cCertLoader, "initialize", rb_win_certstore_loader_initialize, 1);
  rb_define_method(rb_cCertLoader, "each", rb_win_certstore_loader_each, 0);
  rb_define_method(rb_cCertLoader, "find_cert", rb_win_certstore_loader_find_certificate, 1);
}
