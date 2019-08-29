require "helper"
require "openssl"

class CertstoreLoaderTest < ::Test::Unit::TestCase
  def setup
    @loader = Certstore::Loader.new("ROOT")
  end

  def test_loader
    assert_nothing_raised do
      @loader.each
    end
  end

  def test_loader_with_nonexistenct_logical_store
    assert_nothing_raised do
      Certstore::Loader.new("NONEXISTENT")
    end
  end

  def test_get_certificate
    store_name = "ROOT"
    store_loader = Certstore::Loader.new(store_name)
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
    store_loader = Certstore::Loader.new(store_name)

    thumbprint = "Nonexistent"
    assert_raise(Certstore::Loader::CertstoreError) do
      store_loader.find_cert(thumbprint)
    end
  end
end
