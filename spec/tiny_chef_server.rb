#
# Author:: John Keiser (<jkeiser@opscode.com>)
# Copyright:: Copyright (c) 2012 Opscode, Inc.
# License:: Apache License, Version 2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

require 'rubygems'
require 'webrick'
require 'rack'
require 'json'

class TinyChefServer < Rack::Server
  def initialize(options)
    options[:host] ||= "localhost" # TODO 0.0.0.0?
    options[:port] ||= 80
    super(options)
    @data = _data = {
      :clients => {},
      :cookbooks => {},
      :data => {},
      :environments => {
        "_default" => <<EOM
{
  "name": "_default",
  "description": "The default Chef environment",
  "cookbook_versions": {
  },
  "json_class": "Chef::Environment",
  "chef_type": "environment",
  "default_attributes": {
  },
  "override_attributes": {
  }
}
EOM
      },
      :file_store => {},
      :nodes => {},
      :roles => {},
      :sandboxes => {}
    }

    @app = TopLevelEndpoint.new(self)
  end

  attr_reader :data
  attr_reader :app

  private

  class RestBase
    def call(env)
      begin
        rest_path = env['PATH_INFO'].split('/').select { |part| part != "" }
        handler = self
        rest_path.each do |rest_path_part|
          handler = handler.child(rest_path_part)
          if handler.nil?
            return error(404, "Object not found: #{env['REQUEST_PATH']}")
          end
        end
        method = env['REQUEST_METHOD'].downcase.to_sym
        if !handler.respond_to?(method)
          return error(400, "Bad request method for '#{env['REQUEST_PATH']}': #{env['REQUEST_METHOD']}")
        end
        # Dispatch to get()/post()/put()/delete()
        base_uri = "#{env['rack.url_scheme']}://#{env['HTTP_HOST']}#{env['SCRIPT_NAME']}"
        body_io = env['rack.input']
        handler.send(method, rest_path, base_uri, body_io)
      rescue
        puts $!.inspect
        puts $!.backtrace
        raise
      end
    end

    def error(response_code, error)
      json_response(response_code, {"error" => error})
    end

    def json_response(response_code, json)
      already_json_response(response_code, JSON.pretty_generate(json))
    end

    def already_json_response(response_code, json_text)
      [response_code, {"Content-Type" => "application/json"}, json_text]
    end

    def build_uri(base_uri, rest_path)
      "#{base_uri}/#{rest_path.join('/')}"
    end

    def child(name)
      nil
    end
  end

  class TopLevelEndpoint < RestBase
    def initialize(server)
      @server = server
      @children = {
        'clients' => ClientsEndpoint.new(server.data[:clients], 'name'),
        'cookbooks' => CookbooksEndpoint.new(server.data[:cookbooks]),
        'data' => DataBagsEndpoint.new(server.data[:data], 'name'),
        'environments' => EnvironmentsListEndpoint.new(server.data[:environments], 'name'),
        'nodes' => RestListEndpoint.new(server.data[:nodes], 'name'),
        'roles' => RestListEndpoint.new(server.data[:roles], 'name'),
        'sandboxes' => SandboxesEndpoint.new(server.data[:file_store], server.data[:sandboxes]),

        # This endpoint does not exist in the real world.
        'file_store' => FileStoreEndpoint.new(server.data[:file_store])
      }
    end
    def child(name)
      @children[name]
    end
  end

  class RestListEndpoint < RestBase
    def initialize(hash, identity_key)
      @hash = hash
      @identity_key = identity_key
    end

    attr_reader :hash
    attr_reader :identity_key

    def get(rest_path, base_uri, body_io)
      result_hash = {}
      hash.keys.sort.each do |name|
        result_hash[name] = "#{build_uri(base_uri, rest_path + [name])}"
      end
      json_response(200, result_hash)
    end

    def post(rest_path, base_uri, body_io)
      contents = body_io.read
      name = JSON.parse(contents, :create_additions => false)[identity_key]
      if hash[name]
        error(409, "Object already exists")
      else
        hash[name] = contents
        json_response(201, {"uri" => "#{build_uri(base_uri, rest_path + [name])}"})
      end
    end

    def child(name)
      return nil if !hash[name]
      @child_endpoint ||= RestObjectEndpoint.new(hash)
    end
  end

  class RestObjectEndpoint < RestBase
    def initialize(parent_hash)
      @parent_hash = parent_hash
    end

    attr_reader :parent_hash

    def get(rest_path, base_uri, body_io)
      key = rest_path[-1]
      already_json_response(200, parent_hash[key])
    end
    def put(rest_path, base_uri, body_io)
      key = rest_path[-1]
      parent_hash[key] = contents
      already_json_response(200, parent_hash[key])
    end
    def delete(rest_path, base_uri, body_io)
      key = rest_path[-1]
      result = parent_hash[key]
      parent_hash.delete(key)
      already_json_response(200, result)
    end
  end

  class ClientsEndpoint < RestListEndpoint
    PUBLIC_KEY = "-----BEGIN CERTIFICATE-----\nMIIDMzCCApygAwIBAgIBATANBgkqhkiG9w0BAQUFADCBnjELMAkGA1UEBhMCVVMx\nEzARBgNVBAgMCldhc2hpbmd0b24xEDAOBgNVBAcMB1NlYXR0bGUxFjAUBgNVBAoM\nDU9wc2NvZGUsIEluYy4xHDAaBgNVBAsME0NlcnRpZmljYXRlIFNlcnZpY2UxMjAw\nBgNVBAMMKW9wc2NvZGUuY29tL2VtYWlsQWRkcmVzcz1hdXRoQG9wc2NvZGUuY29t\nMB4XDTEyMTEyMTAwMzQyMVoXDTIyMTExOTAwMzQyMVowgZsxEDAOBgNVBAcTB1Nl\nYXR0bGUxEzARBgNVBAgTCldhc2hpbmd0b24xCzAJBgNVBAYTAlVTMRwwGgYDVQQL\nExNDZXJ0aWZpY2F0ZSBTZXJ2aWNlMRYwFAYDVQQKEw1PcHNjb2RlLCBJbmMuMS8w\nLQYDVQQDFCZVUkk6aHR0cDovL29wc2NvZGUuY29tL0dVSURTL3VzZXJfZ3VpZDCC\nASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANLDmPbR71bS2esZlZh/HfC6\n0azXFjl2677wq2ovk9xrUb0Ui4ZLC66TqQ9C/RBzOjXU4TRf3hgPTqvlCgHusl0d\nIcLCrsSl6kPEhJpYWWfRoroIAwf82A9yLQekhqXZEXu5EKkwoUMqyF6m0ZCasaE1\ny8niQxdLAsk3ady/CGQlFqHTPKFfU5UASR2LRtYC1MCIvJHDFRKAp9kPJbQo9P37\nZ8IU7cDudkZFgNLmDixlWsh7C0ghX8fgAlj1P6FgsFufygam973k79GhIP54dELB\nc0S6E8ekkRSOXU9jX/IoiXuFglBvFihAdhvED58bMXzj2AwXUyeAlxItnvs+NVUC\nAwEAATANBgkqhkiG9w0BAQUFAAOBgQBkFZRbMoywK3hb0/X7MXmPYa7nlfnd5UXq\nr2n32ettzZNmEPaI2d1j+//nL5qqhOlrWPS88eKEPnBOX/jZpUWOuAAddnrvFzgw\nrp/C2H7oMT+29F+5ezeViLKbzoFYb4yECHBoi66IFXNae13yj7taMboBeUmE664G\nTB/MZpRr8g==\n-----END CERTIFICATE-----\n"
    PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0sOY9tHvVtLZ6xmVmH8d8LrRrNcWOXbrvvCrai+T3GtRvRSL\nhksLrpOpD0L9EHM6NdThNF/eGA9Oq+UKAe6yXR0hwsKuxKXqQ8SEmlhZZ9GiuggD\nB/zYD3ItB6SGpdkRe7kQqTChQyrIXqbRkJqxoTXLyeJDF0sCyTdp3L8IZCUWodM8\noV9TlQBJHYtG1gLUwIi8kcMVEoCn2Q8ltCj0/ftnwhTtwO52RkWA0uYOLGVayHsL\nSCFfx+ACWPU/oWCwW5/KBqb3veTv0aEg/nh0QsFzRLoTx6SRFI5dT2Nf8iiJe4WC\nUG8WKEB2G8QPnxsxfOPYDBdTJ4CXEi2e+z41VQIDAQABAoIBAALhqbW2KQ+G0nPk\nZacwFbi01SkHx8YBWjfCEpXhEKRy0ytCnKW5YO+CFU2gHNWcva7+uhV9OgwaKXkw\nKHLeUJH1VADVqI4Htqw2g5mYm6BPvWnNsjzpuAp+BR+VoEGkNhj67r9hatMAQr0I\nitTvSH5rvd2EumYXIHKfz1K1SegUk1u1EL1RcMzRmZe4gDb6eNBs9Sg4im4ybTG6\npPIytA8vBQVWhjuAR2Tm+wZHiy0Az6Vu7c2mS07FSX6FO4E8SxWf8idaK9ijMGSq\nFvIS04mrY6XCPUPUC4qm1qNnhDPpOr7CpI2OO98SqGanStS5NFlSFXeXPpM280/u\nfZUA0AECgYEA+x7QUnffDrt7LK2cX6wbvn4mRnFxet7bJjrfWIHf+Rm0URikaNma\nh0/wNKpKBwIH+eHK/LslgzcplrqPytGGHLOG97Gyo5tGAzyLHUWBmsNkRksY2sPL\nuHq6pYWJNkqhnWGnIbmqCr0EWih82x/y4qxbJYpYqXMrit0wVf7yAgkCgYEA1twI\ngFaXqesetTPoEHSQSgC8S4D5/NkdriUXCYb06REcvo9IpFMuiOkVUYNN5d3MDNTP\nIdBicfmvfNELvBtXDomEUD8ls1UuoTIXRNGZ0VsZXu7OErXCK0JKNNyqRmOwcvYL\nJRqLfnlei5Ndo1lu286yL74c5rdTLs/nI2p4e+0CgYB079ZmcLeILrmfBoFI8+Y/\ngJLmPrFvXBOE6+lRV7kqUFPtZ6I3yQzyccETZTDvrnx0WjaiFavUPH27WMjY01S2\nTMtO0Iq1MPsbSrglO1as8MvjB9ldFcvp7gy4Q0Sv6XT0yqJ/S+vo8Df0m+H4UBpU\nf5o6EwBSd/UQxwtZIE0lsQKBgQCswfjX8Eg8KL/lJNpIOOE3j4XXE9ptksmJl2sB\njxDnQYoiMqVO808saHVquC/vTrpd6tKtNpehWwjeTFuqITWLi8jmmQ+gNTKsC9Gn\n1Pxf2Gb67PqnEpwQGln+TRtgQ5HBrdHiQIi+5am+gnw89pDrjjO5rZwhanAo6KPJ\n1zcPNQKBgQDxFu8v4frDmRNCVaZS4f1B6wTrcMrnibIDlnzrK9GG6Hz1U7dDv8s8\nNf4UmeMzDXjlPWZVOvS5+9HKJPdPj7/onv8B2m18+lcgTTDJBkza7R1mjL1Cje/Z\nKcVGsryKN6cjE7yCDasnA7R2rVBV/7NWeJV77bmzT5O//rW4yIfUIg==\n-----END RSA PRIVATE KEY-----\n"
    def post(rest_path, base_uri, body_io)
      result = super(rest_path, base_uri, body_io)
      if result[0] == 201
        uri = JSON.parse(result[2], :create_additions => false)["uri"]
        json_response(201, {
          "uri" => uri,
          "private_key" => PRIVATE_KEY
        })
      end
    end
  end

  class EnvironmentsListEndpoint < RestListEndpoint
    def child(name)
      return nil if !hash[name]
      @child_endpoint ||= EnvironmentsObjectEndpoint.new(hash)
    end
  end

  class EnvironmentsObjectEndpoint < RestObjectEndpoint
    def delete(rest_path, base_uri, body_io)
      if rest_path[-1] == "_default"
        error(403, "_default environment cannot be modified")
      else
        super(rest_path, base_uri, body_io)
      end
    end
  end

  class DataBagsEndpoint < RestListEndpoint
    def child(name)
      child_hash = hash[name]
      return nil if !child_hash
      DataBagEndpoint.new(hash, child_hash)
    end

    def post(rest_path, base_uri, body_io)
      name = JSON.parse(body_io.read, :create_additions => false)[identity_key]
      if hash[name]
        error(409, "Object already exists")
      else
        hash[name] = {}
        json_response(201, {"uri" => "#{build_uri(base_uri, rest_path + [name])}"})
      end
    end
  end

  class DataBagEndpoint < RestListEndpoint
    def initialize(parent_hash, hash)
      super(hash, 'id')
      @parent_hash = parent_hash
    end

    attr_reader :parent_hash

    def delete(rest_path, base_uri, body_io)
      key = rest_path[-1]
      result = parent_hash[key]
      parent_hash.delete(key)
      already_json_response(200, result)
    end
  end

  class SandboxesEndpoint < RestBase
    def initialize(checksums, sandboxes)
      @checksums = checksums
      @sandboxes = sandboxes
      @next_id = 1
    end

    attr_reader :checksums
    attr_reader :sandboxes

    def post(rest_path, base_uri, body_io)
      sandbox_checksums = []

      needed_checksums = JSON.parse(body_io.read, :create_additions => false)['checksums']
      result_checksums = {}
      needed_checksums.keys.each do |needed_checksum|
        if checksums.has_key?(needed_checksum)
          result_checksums[needed_checksum] = { :needs_upload => false }
        else
          result_checksums[needed_checksum] = {
            :needs_upload => true,
            :url => build_uri(base_uri, ['file_store', needed_checksum])
          }
          sandbox_checksums << needed_checksum
        end
      end

      id = @next_id.to_s
      @next_id+=1

      sandboxes[id] = sandbox_checksums

      json_response(201, {
        :uri => build_uri(base_uri, rest_path + [id.to_s]),
        :checksums => result_checksums,
        :sandbox_id => id
      })
    end

    def child(name)
      if sandboxes[name]
        @child_endpoint ||= SandboxEndpoint.new(checksums, sandboxes)
      end
    end
  end

  class SandboxEndpoint < RestBase
    def initialize(checksums, sandboxes)
      @checksums = checksums
      @sandboxes = sandboxes
    end

    attr_reader :checksums
    attr_reader :sandboxes

    def put(rest_path, base_uri, body_io)
      sandboxes.delete(rest_path[-1])
      json_response(200, { :sandbox_id => rest_path[-1]})
    end
  end

  class FileStoreEndpoint < RestBase
    def initialize(file_store)
      @file_store = file_store
    end

    attr_reader :file_store

    def child(name)
      @child_endpoint ||= FileStoreFileEndpoint.new(file_store)
    end
  end

  class FileStoreFileEndpoint < RestBase
    def initialize(file_store)
      @file_store = file_store
    end

    attr_reader :file_store

    def get(rest_path, base_uri, body_io)
      filename = rest_path[-1]
      if file_store[filename]
        [200, {"Content-Type" => 'application/x-binary'}, file_store[filename] ]
      else
        error(404, "File not found: '#{filename}'")
      end
    end

    def put(rest_path, base_uri, body_io)
      file_store[rest_path[-1]] = body_io.read
      json_response(200, {})
    end
  end

  class CookbooksBase < RestBase
    def initialize(cookbooks)
      @cookbooks = cookbooks
    end

    attr_reader :cookbooks

    def format_cookbooks_list(rest_path, base_uri, cookbooks_list)
      results = {}
      cookbooks_list.keys.sort.each do |name|
        versions = cookbooks_list[name].keys.sort.map do |version|
          {
            'url' => build_uri(base_uri, rest_path + [name, version]),
            'version' => version
          }
        end
        results[name] = {
          'url' => build_uri(base_uri, rest_path + [name]),
          'versions' => versions
        }
      end
      results
    end
  end

  class CookbooksEndpoint < CookbooksBase
    def get(rest_path, base_uri, body_io)
      json_response(200, format_cookbooks_list(rest_path, base_uri, cookbooks))
    end

    def child(name)
      @child_endpoint ||= CookbookEndpoint.new(cookbooks)
    end
  end

  class CookbookEndpoint < CookbooksBase
    def get(rest_path, base_uri, body_io)
      name = rest_path[-1]
      json_response(200, format_cookbooks_list(rest_path, base_uri, { name => cookbooks[name] }))
    end

    def child(name)
      @child_endpoint ||= CookbookVersionEndpoint.new(cookbooks)
    end
  end

  class CookbookVersionEndpoint < CookbooksBase
    def get(rest_path, base_uri, body_io)
      name = rest_path[-2]
      version = rest_path[-1]
      return error(404, "No cookbook named #{name}") if !cookbooks[name]
      if version == "_latest"
        # TODO it is highly unlikely that this is the real sort.
        version = cookbooks[name].keys.sort[-1]
      end
      return error(404, "No #{name} cookbooks with version #{version}") if !cookbooks[name][version]
      already_json_response(200, cookbooks[name][version])
    end

    def put(rest_path, base_uri, body_io)
      name = rest_path[-2]
      version = rest_path[-1]
      cookbooks[name] = {} if !cookbooks[name]
      response_code = cookbooks[name][version] ? 200 : 201
      cookbooks[name][version] = body_io.read
      already_json_response(response_code, cookbooks[name][version])
    end

    def delete(rest_path, base_uri, body_io)
      name = rest_path[-2]
      version = rest_path[-1]
      return error(404, "No cookbook named #{name}") if !cookbooks[name]
      return error(404, "No #{name} cookbooks with version #{version}") if !cookbooks[name][version]
      response = cookbooks[name][version]
      cookbooks[name].delete(version)
      cookbooks.delete(name) if cookbooks[name].size == 0
      already_json_response(200, response)
    end
  end
end

server = TinyChefServer.new(:Port => 8889)
server.start
