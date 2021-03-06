#!/usr/bin/env ruby

# Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "json"
require "yaml"
require "base64"
require "openssl"
require "httparty"

#
# Network
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
end

def request_kdf_iteration_count username, http
    response = http.post_json "https://vault.bitwarden.com/api/accounts/prelogin", email: username
    raise "Failed to request KDF iteration count" if !response.ok?

    response.parsed_response["KdfIterations"]
end

def request_auth_token username, password_hash, http
    response = http.post_form "https://vault.bitwarden.com/identity/connect/token", {
        username: username,
        password: password_hash,
        grant_type: "password",
        scope: "api offline_access",
        client_id: "web",
    }
    raise "Failed to request auth token" if !response.ok?

    token_type = response.parsed_response["token_type"]
    access_token = response.parsed_response["access_token"]

    "#{token_type} #{access_token}"
end

def logout http
    # TODO: Looks like there's nothing to do here.
    #       The logout doesn't do anything server-side.
    #       See if this ever changes.
end

def download_vault auth_token, http
    response = http.get "https://vault.bitwarden.com/api/sync?excludeDomains=true",
                        {"Authorization" => auth_token}
    raise "Failed to download the vault" if !response.ok?

    response.parsed_response
end

def decrypt_vault encrypted_vault, key
    encrypted_vault_key = encrypted_vault["Profile"]["Key"]
    vault_key = if encrypted_vault_key.nil?
        key
    else
        decrypt_string encrypted_vault_key, key
    end

    accounts = encrypted_vault["Ciphers"]
        .select { |item| item["Type"] == 1 }
        .map { |item|
            {
                id: item["Id"],
                name: decrypt_string(item["Name"], vault_key),
                username: decrypt_string(item["Login"]["Username"], vault_key),
                password: decrypt_string(item["Login"]["Password"], vault_key),
                urls: item["Login"]["Uris"].map { |uri| decrypt_string(uri["Uri"], vault_key) },
                notes: decrypt_string(item["Notes"], vault_key),
            }
        }

    accounts
end

def decrypt_string s, key
    decrypt_cipher_string CipherString.parse(s), key
end

def decrypt_cipher_string cs, key
    cs.decrypt key
end

#
# Crypto
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
        hash_password(password, key).e64
    end

    def self.pbkdf2 password:, salt:, iterations:
        OpenSSL::KDF.pbkdf2_hmac password,
                                 salt: salt,
                                 iterations: iterations,
                                 length: 32,
                                 hash: "sha256"
    end

    def self.hmac key, message
        OpenSSL::HMAC.digest "sha256", key, message
    end

    # This is the "expand" half of the "extract-expand" HKDF algorithm.
    # The length is fixed to 32 not to complicate things.
    # See https://tools.ietf.org/html/rfc5869
    def self.hkdf_expand prk:, info:
        hmac prk, info + "\x01"
    end

    def self.expand_key key
        fail "Key must be 32 bytes long" if key.size != 32
        enc = hkdf_expand prk: key, info: "enc"
        mac = hkdf_expand prk: key, info: "mac"

        enc + mac
    end

    def self.decrypt_aes256cbc ciphertext, iv, key
        c = OpenSSL::Cipher.new("aes-256-cbc")
        c.decrypt
        c.key = key
        c.iv = iv
        c.update(ciphertext) + c.final
    end
end

class CipherString < Struct.new :mode, :iv, :ciphertext, :mac
    AES_256_CBC = 0
    AES_128_CBC_HMAC_SHA_256 = 1
    AES_256_CBC_HMAC_SHA_256 = 2

    def self.parse s
        mode, encrypted = mode_encrypted s
        iv, ciphertext, mac = iv_cipthertext_mac encrypted
        validate mode, iv, ciphertext, mac

        new mode, iv, ciphertext, mac
    end

    def self.mode_encrypted s
        parts = s.split "."
        case parts.size
        when 1
            [AES_256_CBC, parts[0]]
        when 2
            [parts[0].to_i, parts[1]]
        else
            fail "Invalid cipher string"
        end
    end

    def self.iv_cipthertext_mac s
        parts = s.split "|"
        case parts.size
        when 1
            fail "Invalid cipher string"
        when 2
            [parts[0].d64, parts[1].d64, nil]
        when 3
            [parts[0].d64, parts[1].d64, parts[2].d64]
        else
            fail "Invalid cipher string"
        end
    end

    def self.validate mode, iv, ciphertext, mac
        fail "IV must be 16 bytes long" if iv.nil? || iv.size != 16
        fail "Ciphertext must be present" if ciphertext.nil?

        case mode
        when AES_256_CBC
            fail "MAC is not supported in AES-256-CBC mode" if mac
        when AES_128_CBC_HMAC_SHA_256, AES_256_CBC_HMAC_SHA_256
            fail "MAC must be 32 bytes long" if mac.nil? || mac.size != 32
        else
            fail "Invalid encryption mode"
        end
    end

    def decrypt key
        case mode
        when 0
            fail "Key must be 32 bytes long" if key.size != 32

            Crypto.decrypt_aes256cbc ciphertext, iv, key
        when 1
            # TODO: Handle this case
            fail "Not supported yet"
        when 2
            key = Crypto.expand_key key if key.size == 32
            fail "Key must be 64 bytes long" if key.size != 64

            computed_mac = Crypto.hmac key[32, 32], iv + ciphertext
            fail "MAC doesn't match" if computed_mac != mac

            Crypto.decrypt_aes256cbc ciphertext, iv, key[0, 32]
        end
    end
end

#
# Utils
#

class String
    def e64
        Base64.strict_encode64 self
    end

    def d64
        Base64.strict_decode64 self
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

offile_vault_filename = config["testing-offile-vault"]
kdf_iterations = config["testing-kdf-iterations"]

if offile_vault_filename && kdf_iterations
    key = Crypto.derive_key username, password, kdf_iterations
    encrypted_vault = JSON.load File.read offile_vault_filename
    ap decrypt_vault encrypted_vault, key
else
    kdf_iterations = request_kdf_iteration_count username, http
    key = Crypto.derive_key username, password, kdf_iterations
    hash = Crypto.hash_password_base64 password, key
    auth_token = request_auth_token username, hash, http

    begin
        encrypted_vault = download_vault auth_token, http
        ap decrypt_vault encrypted_vault, key
    ensure
        logout http
    end
end
