#!/usr/bin/env ruby

# Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "json"
require "yaml"
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

    def get url
        self.class.get url
    end

    def post url, args, headers = {}
        self.class.post url,
                        body: args.to_json,
                        headers: headers.merge(@json_headers)
    end
end


def prelogin username, http
    response = http.post "https://vault.bitwarden.com/api/accounts/prelogin", email: username
    response.parsed_response
end

#
# main
#

# Set up and prepare the credentials
http = Http.new
config = YAML::load_file "config.yaml"

ap prelogin config["username"], http
