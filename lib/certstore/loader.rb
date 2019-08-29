require "certstore/certstore"
module Certstore
  class Loader
    alias_method :initialize_raw, :initialize

    class InvalidStoreNameError < StandardError; end

    def initialize(store_name)
      unless store_name && valid_logical_store_list.include?(store_name.upcase)
        raise InvalidStoreNameError, "'#{store_name}' is not a valid logical store name"
      end
      initialize_raw(store_name)
    end

    def valid_logical_store_list
      %w[MY CA ROOT AUTHROOT DISALLOWED SPC TRUST TRUSTEDPEOPLE TRUSTEDPUBLISHER CLIENTAUTHISSUER TRUSTEDDEVICES SMARTCARDROOT WEBHOSTING REMOTE\ DESKTOP]
    end
  end
end
