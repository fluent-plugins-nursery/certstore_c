require_relative "./helper"

class CertstoreOpenSSLLoaderTest < ::Test::Unit::TestCase
  def create_loader(cert_logical_store_name, enterprise: false)
    cert_store = OpenSSL::X509::Store.new

    Certstore::OpenSSL::Loader.new(cert_store, cert_logical_store_name, enterprise: enterprise)
  end

  def test_load_cert_store
    assert_nothing_raised do
      loader = create_loader("Trust")
      loader.load_cert_store
    end
  end

  def test_load_cert_store_with_noexistent_logical_store_name
    assert_raise(Certstore::Loader::InvalidStoreNameError) do
      loader = create_loader("Noexistent")
      loader.load_cert_store
    end
  end

  def test_get_certificate
    store_name = "ROOT"
    loader = create_loader(store_name)
    store_loader = Certstore::Loader.new(store_name, enterprise: false)
    certificate_thumbprints = []
    store_loader.each do |pem|
      x509_certificate_obj = OpenSSL::X509::Certificate.new(pem)
      certificate_thumbprints << OpenSSL::Digest::SHA1.new(x509_certificate_obj.to_der).to_s
    end

    thumbprint = certificate_thumbprints.first
    openssl_x509_obj = loader.get_certificate(thumbprint)
    assert_true openssl_x509_obj.is_a?(OpenSSL::X509::Certificate)
    assert_true loader.valid_duration?(openssl_x509_obj)
  end

  def test_get_certificate_with_nonexistent_thumbprint
    loader = create_loader("ROOT")
    assert_raise(Certstore::Loader::LoaderError) do
      loader.get_certificate("nonexistent")
    end
  end

  def test_export_pkcs12
    omit "Ruby 2.3 DevKit seems not to be able to support it properly" unless RUBY_VERSION >= "2.4.0"
    require 'securerandom'

    store_name = "ROOT"
    loader = create_loader(store_name)
    store_loader = Certstore::Loader.new(store_name, enterprise: false)
    certificate_thumbprints = []
    store_loader.each do |pem|
      x509_certificate_obj = OpenSSL::X509::Certificate.new(pem)
      certificate_thumbprints << OpenSSL::Digest::SHA1.new(x509_certificate_obj.to_der).to_s
    end

    thumbprint = certificate_thumbprints.first
    password = SecureRandom.hex(10)
    openssl_pkcs12_obj = loader.export_pkcs12(thumbprint, password)
    assert_true openssl_pkcs12_obj.is_a?(OpenSSL::PKCS12)
    ca_certs = openssl_pkcs12_obj.ca_certs
    if not ca_certs.empty?
      assert_true loader.valid_duration?(ca_certs.first)
    end
  end

  def test_export_pkcs12_with_nonexistent_thumbprint
    loader = create_loader("ROOT")
    assert_raise(Certstore::Loader::LoaderError) do
      loader.export_pkcs12("nonexistent", "passwd")
    end
  end

  class AddAndDeleteCert < self
    def setup
      store_name = "ROOT"
      @loader = create_loader(store_name)
      @loader.delete_certificate("4b34e3c6fa22f11902c3b892811d7afd50af2453") rescue nil
    end

    def test_add_and_delete_certificate
      @loader.add_certificate(File.join(__dir__, "data", "ca_cert.pem"))
      assert_true @loader.delete_certificate("4b34e3c6fa22f11902c3b892811d7afd50af2453")
    end
  end
end
