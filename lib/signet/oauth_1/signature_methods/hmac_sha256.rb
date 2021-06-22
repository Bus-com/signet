require "openssl"
require "signet"

module Signet #:nodoc:
  module OAuth1
    module HMACSHA256
      def self.generate_signature(base_string, client_credential_secret, token_credential_secret)
        client_credential_secret = Signet::OAuth1.encode client_credential_secret
        token_credential_secret = Signet::OAuth1.encode token_credential_secret

        key = [client_credential_secret, token_credential_secret].join("&")
        Base64.encode64(OpenSSL::HMAC.digest(OpenSSL::Digest.new("sha256"), key, base_string)).strip
      end
    end
  end
end
