$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)
require "certstore"
require "test-unit"
require "openssl"

TEST_CERT_PATH = File.join(__dir__, "data", "ca_cert.pem")

def get_test_cert_hash
  File.open(TEST_CERT_PATH) do |file|
    OpenSSL::Digest::SHA1.new(OpenSSL::X509::Certificate.new(file.read).to_der)
  end
end
