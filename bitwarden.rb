#!/usr/bin/env ruby

# Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "json"
require "yaml"
require "base64"
require "openssl"
require "httparty"

#
# network
#

class Http
    include HTTParty

    def initialize
        @json_headers = {
            "Content-Type" => "application/json; charset=UTF-8"
        }
    end

    def get url, headers = {}
        self.class.get url, headers: headers
    end

    def post url, args, headers = {}
        self.class.post url,
                        body: args.to_json,
                        headers: @json_headers.merge(headers)
    end
end

def request_kdf_iteration_count username, http
    response = http.post "https://vault.bitwarden.com/api/accounts/prelogin", email: username
    response.ok? && response.parsed_response["KdfIterations"] || 5000
end

#
# crypto
#

module Crypto
    def self.derive_key username, password, iterations
        pbkdf2 password: password,
               salt: username.strip.downcase,
               iterations: iterations
    end

    def self.hash_password password, key
        pbkdf2 password: key,
               salt: password,
               iterations: 1
    end

    def self.hash_password_base64 password, key
        Base64.strict_encode64 hash_password password, key
    end

    def self.pbkdf2 password:, salt:, iterations:
        OpenSSL::KDF.pbkdf2_hmac password,
                                 salt: salt,
                                 iterations: iterations,
                                 length: 32,
                                 hash: "sha256"
    end
end

#
# main
#

# Set up and prepare the credentials
http = Http.new
config = YAML::load_file "config.yaml"

username = config["username"] or fail "Username is missing"
password = config["password"] or fail "Password is missing"

kdf_iterations = request_kdf_iteration_count username, http
key = Crypto.derive_key username, password, kdf_iterations
hash = Crypto.hash_password_base64 password, key

ap key
ap hash
