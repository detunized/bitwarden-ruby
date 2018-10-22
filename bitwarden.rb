#!/usr/bin/env ruby

# Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "yaml"
require "httparty"

#
# network
#

class Http
    include HTTParty

    def get url
        self.class.get url
    end

    def post url, args
        self.class.post url, body: args
    end
end


#
# main
#

# Set up and prepare the credentials
http = Http.new
config = YAML::load_file "config.yaml"

ap config
