require_relative "./helper"
require "openssl"

class CertstoreLoaderTest < ::Test::Unit::TestCase
  def setup
    @loader = Certstore::Loader.new("ROOT", enterprise: false)
  end

  def test_loader
    assert_nothing_raised do
      @loader.each
    end
  end

  def test_loader_with_nonexistenct_logical_store
    assert_raise(Certstore::Loader::InvalidStoreNameError) do
      Certstore::Loader.new("NONEXISTENT", enterprise: false)
    end
  end

  def test_get_certificate
    store_name = "ROOT"
    store_loader = Certstore::Loader.new(store_name, enterprise: false)
    certificate_thumbprints = []
    store_loader.each do |pem|
      x509_certificate_obj = OpenSSL::X509::Certificate.new(pem)
      certificate_thumbprints << OpenSSL::Digest::SHA1.new(x509_certificate_obj.to_der).to_s
    end

    thumbprint = certificate_thumbprints.first
    pem = store_loader.find_cert(thumbprint)
    openssl_x509_obj = OpenSSL::X509::Certificate.new(pem)
    assert_true openssl_x509_obj.is_a?(OpenSSL::X509::Certificate)
  end

  def test_get_non_existent_certificate
    store_name = "ROOT"
    store_loader = Certstore::Loader.new(store_name, enterprise: false)

    thumbprint = "Nonexistent"
    assert_raise(Certstore::Loader::LoaderError) do
      store_loader.find_cert(thumbprint)
    end
  end

  def test_export_pfx
    omit "Ruby 2.3 DevKit seems not to be able to support it properly" unless RUBY_VERSION >= "2.4.0"
    require 'securerandom'

    store_name = "ROOT"
    store_loader = Certstore::Loader.new(store_name, enterprise: false)
    certificate_thumbprints = []
    store_loader.each do |pem|
      x509_certificate_obj = OpenSSL::X509::Certificate.new(pem)
      certificate_thumbprints << OpenSSL::Digest::SHA1.new(x509_certificate_obj.to_der).to_s
    end

    thumbprint = certificate_thumbprints.first
    password = SecureRandom.hex(10)
    pkcs12 = store_loader.export_pfx(thumbprint, password)
    openssl_pkcs12_obj = OpenSSL::PKCS12.new(pkcs12, password)
    assert_true openssl_pkcs12_obj.is_a?(OpenSSL::PKCS12)
  end

  def test_export_pfx_with_non_existent_thumbprint
    store_name = "ROOT"
    store_loader = Certstore::Loader.new(store_name, enterprise: false)

    thumbprint = "Nonexistent"
    assert_raise(Certstore::Loader::LoaderError) do
      store_loader.export_pfx(thumbprint, "passwd")
    end
  end

  class AddAndDeleteCert < self
    def setup
      store_name = "ROOT"
      @store_loader = Certstore::Loader.new(store_name, enterprise: false)
      @store_loader.delete_cert(get_test_cert_hash.to_s) rescue nil
    end

    def test_add_and_delete_certificate
      File.open(TEST_CERT_PATH) do |file|
        @store_loader.add_cert(OpenSSL::X509::Certificate.new(file.read).to_der)
      end
      assert_true @store_loader.delete_cert(get_test_cert_hash.to_s)
    end
  end
end
