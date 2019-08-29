require "certstore/certstore"
require "openssl"

module Certstore
  module OpenSSL
    class Loader
      attr_reader :cert_store

      def initialize(cert_store, store_name)
        @cert_store = cert_store
        @store_name = store_name
        @loader = Certstore::Loader.new(@store_name)
      end

      def load_cert_store
        @loader.each do |pem|
          begin
            x509_certificate_obj = ::OpenSSL::X509::Certificate.new(pem)
            @cert_store.add_cert(x509_certificate_obj)
          rescue ::OpenSSL::X509::StoreError => e # continue to read
            @log.warn "failed to load certificate(thumbprint: #{OpenSSL::Digest::SHA1.new(x509_certificate_obj.to_der).to_s}) from certstore", error: e
          end
        end
      end

      def get_certificate(thumbprint)
        ::OpenSSL::X509::Certificate.new(@loader.find_cert(thumbprint))
      end
    end
  end
end
