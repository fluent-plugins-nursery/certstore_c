require "certstore/certstore"
require "openssl"
require "logger"

module Certstore
  module OpenSSL
    class Loader
      attr_reader :cert_store

      def initialize(log = Logger.new(STDOUT), cert_store, store_name)
        @log = log
        @cert_store = cert_store
        @store_name = store_name
        @loader = Certstore::Loader.new(@store_name)
      end

      def load_cert_store
        @loader.each do |pem|
          begin
            x509_certificate_obj = ::OpenSSL::X509::Certificate.new(pem)
            valid_duration?(x509_certificate_obj)
            @cert_store.add_cert(x509_certificate_obj)
          rescue ::OpenSSL::X509::StoreError => e # continue to read
            @log.warn "failed to load certificate(thumbprint: #{OpenSSL::Digest::SHA1.new(x509_certificate_obj.to_der).to_s}) from certstore", error: e
          end
        end
      end

      def cleanup_thumbprint(thumbprint)
        thumbprint.gsub(/[^A-Za-z0-9]/, "")
      end

      def get_certificate(thumbprint)
        thumbprint = cleanup_thumbprint(thumbprint)
        ::OpenSSL::X509::Certificate.new(@loader.find_cert(thumbprint))
      end

      def valid_duration?(x509_obj)
        x509_obj.not_before < Time.now.utc && x509_obj.not_after > Time.now.utc
      end
    end
  end
end
