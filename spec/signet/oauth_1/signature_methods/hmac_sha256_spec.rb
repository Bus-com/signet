require "spec_helper"
require "signet"
require "signet/oauth_1"
require "signet/oauth_1/signature_methods/hmac_sha256"

describe Signet::OAuth1::HMACSHA256 do
  it "should correctly generate a signature" do
    method = "GET"
    uri = "http://photos.example.net/photos"
    parameters = {
      "oauth_consumer_key"     => "dpf43f3p2l4k3l03",
      "oauth_token"            => "nnch734d00sl2jdk",
      "oauth_signature_method" => "HMAC-SHA256",
      "oauth_timestamp"        => "1191242096",
      "oauth_nonce"            => "kllo9940pd9333jh",
      "oauth_version"          => "1.0",
      "file"                   => "vacation.jpg",
      "size"                   => "original"
    }
    client_credential_secret = "kd94hf93k423kf44"
    token_credential_secret = "pfkkdhi9sl3r4s00"
    base_string = Signet::OAuth1.generate_base_string method, uri, parameters
    expect(Signet::OAuth1::HMACSHA256.generate_signature(
             base_string, client_credential_secret, token_credential_secret
           )).to eq "WVPzl1j6ZsnkIjWr7e3OZ3jkenL57KwaLFhYsroX1hg="
  end

  it "should correctly generate a signature" do
    method = "GET"
    uri = "http://photos.example.net/photos"
    parameters = {
      "oauth_consumer_key"     => "www.example.com",
      "oauth_token"            => "4/QL2GT6b5uznYem1ZGH6v+-9mMvRL",
      "oauth_signature_method" => "HMAC-SHA1",
      "oauth_timestamp"        => "1191242096",
      "oauth_nonce"            => "kllo9940pd9333jh",
      "oauth_version"          => "1.0",
      "file"                   => "vacation.jpg",
      "size"                   => "original"
    }
    client_credential_secret = "Kv+o2XXL/9RxkQW3lO3QTVlH"
    token_credential_secret = "QllSuL9eQ5FXFO1Z/HcgL4ON"
    base_string = Signet::OAuth1.generate_base_string method, uri, parameters
    expect(Signet::OAuth1::HMACSHA256.generate_signature(
             base_string, client_credential_secret, token_credential_secret
           )).to eq "gB6w7pa+J+O4ha0Kz2h+TMNSkXrgAqgFBZivZ8EC/fM="
  end
end
