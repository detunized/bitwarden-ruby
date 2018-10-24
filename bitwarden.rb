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
        @post_json_headers = {
            "Accept" => "application/json",
            "Content-Type" => "application/json; charset=UTF-8"
        }
        @post_form_headers = {
            "Accept" => "application/json",
            "Content-Type" => "application/x-www-form-urlencoded; charset=UTF-8"
        }
    end

    def get url, headers = {}
        self.class.get url, headers: headers
    end

    def post_json url, args, headers = {}
        self.class.post url,
                        body: args.to_json,
                        headers: @post_json_headers.merge(headers)
    end

    def post_form url, args, headers = {}
        self.class.post url,
                        body: args,
                        headers: @post_form_headers.merge(headers)
    end

    def put url, headers = {}
        self.class.put url, headers: headers
    end
end

def request_kdf_iteration_count username, http
    response = http.post_json "https://vault.bitwarden.com/api/accounts/prelogin", email: username
    response.ok? && response.parsed_response["KdfIterations"] || 5000
end

def request_auth_token username, password_hash, http
    response = http.post_form "https://vault.bitwarden.com/identity/connect/token", {
        username: username,
        password: password_hash,
        grant_type: "password",
        scope: "api offline_access",
        client_id: "web",
    }
    response.ok? && response.parsed_response
end

def logout device_id, http
    response = http.put "https://vault.bitwarden.com/api/devices/identifier/#{device_id}/clear-token",
    response.ok? && response.parsed_response
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
auth_token = request_auth_token username, hash, http

ap auth_token

logout "TODO", http
