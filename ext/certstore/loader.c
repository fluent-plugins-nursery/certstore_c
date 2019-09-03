/* certstore_c */
/* Licensed under the Apache License, Version 2.0 (the "License"); */
/* you may not use this file except in compliance with the License. */
/* You may obtain a copy of the License at */
/*     http://www.apache.org/licenses/LICENSE-2.0 */
/* Unless required by applicable law or agreed to in writing, software */
/* distributed under the License is distributed on an "AS IS" BASIS, */
/* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. */
/* See the License for the specific language governing permissions and */
/* limitations under the License. */

#include <certstore.h>

static void certstore_loader_free(void *certstore);

static const rb_data_type_t rb_win_certstore_loader_type = {
  "winevt/certstore_loader", {
    0, certstore_loader_free, 0,
  }, NULL, NULL,
  RUBY_TYPED_FREE_IMMEDIATELY
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
rb_win_certstore_loader_initialize(VALUE self, VALUE store_name, VALUE use_enterprise)
{
  VALUE vStoreName;
  struct CertstoreLoader *loader;
  DWORD len;

  Check_Type(store_name, T_STRING);

  // store_name : To wide char
  len = MultiByteToWideChar(CP_UTF8, 0, RSTRING_PTR(store_name), RSTRING_LEN(store_name), NULL, 0);
  PWSTR winStoreName = ALLOCV_N(WCHAR, vStoreName, len+1);
  MultiByteToWideChar(CP_UTF8, 0, RSTRING_PTR(store_name), RSTRING_LEN(store_name), winStoreName, len);
  winStoreName[len] = L'\0';

  TypedData_Get_Struct(self, struct CertstoreLoader, &rb_win_certstore_loader_type, loader);

  if (RTEST(use_enterprise)) {
    loader->hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE, winStoreName);
  } else {
    loader->hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE, winStoreName);
  }
  ALLOCV_END(vStoreName);

  return Qnil;
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
  xfree(utf8str);
  free(wszString);
  free(certificate);

  return rb_pem;

error:
  xfree(utf8str);
  free(wszString);
  free(certificate);

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

  // thumbprint : To wide char
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
  ALLOCV_END(vThumbprint);

  return rb_certificate;

error:

  CertFreeCertificateContext(pContext);

  sprintf(errBuf, "Cannot find certificates with thumbprint(%S)", winThumbprint);
  rb_raise(rb_eCertLoaderError, errBuf);
}

static VALUE
rb_win_certstore_loader_export_pfx(VALUE self, VALUE rb_thumbprint, VALUE rb_password)
{
  VALUE vThumbprint;
  PCCERT_CONTEXT pContext = NULL;
  struct CertstoreLoader *loader;
  DWORD len;
  CHAR errBuf[256];
  HCERTSTORE hMemoryStore = NULL;
  VALUE vPassword;
  CRYPT_DATA_BLOB pfxPacket;

  TypedData_Get_Struct(self, struct CertstoreLoader, &rb_win_certstore_loader_type, loader);

  // thumbprint : To wide char
  len = MultiByteToWideChar(CP_UTF8, 0, RSTRING_PTR(rb_thumbprint), RSTRING_LEN(rb_thumbprint), NULL, 0);
  WCHAR *winThumbprint = ALLOCV_N(WCHAR, vThumbprint, len+1);
  MultiByteToWideChar(CP_UTF8, 0, RSTRING_PTR(rb_thumbprint), RSTRING_LEN(rb_thumbprint), winThumbprint, len);
  winThumbprint[len] = L'\0';
  // password : To wide char
  len = MultiByteToWideChar(CP_UTF8, 0, RSTRING_PTR(rb_password), RSTRING_LEN(rb_password), NULL, 0);
  WCHAR *winPassword = ALLOCV_N(WCHAR, vPassword, len+1);
  MultiByteToWideChar(CP_UTF8, 0, RSTRING_PTR(rb_password), RSTRING_LEN(rb_password), winPassword, len);
  winPassword[len] = L'\0';

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
  if (!pContext) {
    sprintf(errBuf, "Cannot find certificates with thumbprint(%S)", winThumbprint);

    goto error;
  }

  hMemoryStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
  CertAddCertificateContextToStore(hMemoryStore, pContext, CERT_STORE_ADD_ALWAYS, NULL);

  pfxPacket.pbData = NULL;
  if (!PFXExportCertStoreEx(hMemoryStore, &pfxPacket, winPassword, NULL, EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY)) {
    sprintf(errBuf, "Cannot export pfx certificate with thumbprint(%S)", winThumbprint);

    goto error;
  }

  pfxPacket.pbData = (LPBYTE)CryptMemAlloc(pfxPacket.cbData);
  if (!PFXExportCertStoreEx(hMemoryStore, &pfxPacket, winPassword, NULL, EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY)) {
    sprintf(errBuf, "Cannot export pfx certificate with thumbprint(%S)", winThumbprint);

    CryptMemFree(pfxPacket.pbData);

    goto error;
  }
  ALLOCV_END(vThumbprint);
  ALLOCV_END(vPassword);

  VALUE rb_str = rb_str_new(pfxPacket.pbData, pfxPacket.cbData);

  CryptMemFree(pfxPacket.pbData);
  CertCloseStore(hMemoryStore, CERT_CLOSE_STORE_CHECK_FLAG);
  CertFreeCertificateContext(pContext);

  return rb_str;

error:
  ALLOCV_END(vThumbprint);
  ALLOCV_END(vPassword);

  if (pContext)
    CertFreeCertificateContext(pContext);
  if (hMemoryStore)
    CertCloseStore(hMemoryStore, CERT_CLOSE_STORE_CHECK_FLAG);

  rb_raise(rb_eCertLoaderError, errBuf);
}

void
Init_certstore_loader(VALUE rb_mCertstore)
{
  rb_cCertLoader = rb_define_class_under(rb_mCertstore, "Loader", rb_cObject);
  rb_eCertLoaderError = rb_define_class_under(rb_cCertLoader, "LoaderError", rb_eStandardError);

  rb_define_alloc_func(rb_cCertLoader, rb_win_certstore_loader_alloc);
  rb_define_method(rb_cCertLoader, "initialize", rb_win_certstore_loader_initialize, 2);
  rb_define_method(rb_cCertLoader, "each", rb_win_certstore_loader_each, 0);
  rb_define_method(rb_cCertLoader, "find_cert", rb_win_certstore_loader_find_certificate, 1);
  rb_define_method(rb_cCertLoader, "export_pfx", rb_win_certstore_loader_export_pfx, 2);
}