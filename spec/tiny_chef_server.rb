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
require 'chef/exceptions'
require 'chef/version_class'
require 'chef/version_constraint'

class TinyChefServer < Rack::Server
  def initialize(options)
    options[:host] ||= "localhost" # TODO 0.0.0.0?
    options[:port] ||= 80
    super(options)
    @data = {
      'clients' => {
        'chef-validator' => '{ "validator": true }',
        'chef-webui' => '{ "admin": true }'
      },
      'cookbooks' => {},
      'data' => {},
      'environments' => {
        '_default' => '{ "description": "The default Chef environment" }'
      },
      'file_store' => {},
      'nodes' => {},
      'roles' => {},
      'sandboxes' => {},
      'users' => {}
    }
  end

  attr_reader :data

  def app
    @app ||= begin
      router = Router.new([
        [ '/authenticate_user', AuthenticateUserEndpoint.new(data) ],
        [ '/clients', ActorsEndpoint.new(data) ],
        [ '/clients/*', ActorEndpoint.new(data) ],
        [ '/cookbooks', CookbooksEndpoint.new(data) ],
        [ '/cookbooks/*', CookbookEndpoint.new(data) ],
        [ '/cookbooks/*/*', CookbookVersionEndpoint.new(data) ],
        [ '/data', DataBagsEndpoint.new(data) ],
        [ '/data/*', DataBagEndpoint.new(data) ],
        [ '/data/*/*', DataBagItemEndpoint.new(data) ],
        [ '/environments', RestListEndpoint.new(data) ],
        [ '/environments/*', EnvironmentEndpoint.new(data) ],
        [ '/environments/*/cookbooks', EnvironmentCookbooksEndpoint.new(data) ],
        [ '/environments/*/cookbooks/*', EnvironmentCookbookEndpoint.new(data) ],
        [ '/environments/*/cookbook_versions', EnvironmentCookbookVersionsEndpoint.new(data) ],
        [ '/environments/*/nodes', EnvironmentNodesEndpoint.new(data) ],
        [ '/nodes', RestListEndpoint.new(data) ],
        [ '/nodes/*', RestObjectEndpoint.new(data) ],
        [ '/roles', RestListEndpoint.new(data) ],
        [ '/roles/*', RestObjectEndpoint.new(data) ],
        [ '/sandboxes', SandboxesEndpoint.new(data) ],
        [ '/sandboxes/*', SandboxEndpoint.new(data) ],
        [ '/search', SearchesEndpoint.new(data) ],
        [ '/search/*', SearchEndpoint.new(data) ],
        [ '/users', ActorsEndpoint.new(data) ],
        [ '/users/*', ActorEndpoint.new(data) ],

        [ '/file_store/*', FileStoreFileEndpoint.new(data) ],
      ])
      router.not_found = NotFoundEndpoint.new
      router
    end
  end

  CERTIFICATE = "-----BEGIN CERTIFICATE-----\nMIIDMzCCApygAwIBAgIBATANBgkqhkiG9w0BAQUFADCBnjELMAkGA1UEBhMCVVMx\nEzARBgNVBAgMCldhc2hpbmd0b24xEDAOBgNVBAcMB1NlYXR0bGUxFjAUBgNVBAoM\nDU9wc2NvZGUsIEluYy4xHDAaBgNVBAsME0NlcnRpZmljYXRlIFNlcnZpY2UxMjAw\nBgNVBAMMKW9wc2NvZGUuY29tL2VtYWlsQWRkcmVzcz1hdXRoQG9wc2NvZGUuY29t\nMB4XDTEyMTEyMTAwMzQyMVoXDTIyMTExOTAwMzQyMVowgZsxEDAOBgNVBAcTB1Nl\nYXR0bGUxEzARBgNVBAgTCldhc2hpbmd0b24xCzAJBgNVBAYTAlVTMRwwGgYDVQQL\nExNDZXJ0aWZpY2F0ZSBTZXJ2aWNlMRYwFAYDVQQKEw1PcHNjb2RlLCBJbmMuMS8w\nLQYDVQQDFCZVUkk6aHR0cDovL29wc2NvZGUuY29tL0dVSURTL3VzZXJfZ3VpZDCC\nASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANLDmPbR71bS2esZlZh/HfC6\n0azXFjl2677wq2ovk9xrUb0Ui4ZLC66TqQ9C/RBzOjXU4TRf3hgPTqvlCgHusl0d\nIcLCrsSl6kPEhJpYWWfRoroIAwf82A9yLQekhqXZEXu5EKkwoUMqyF6m0ZCasaE1\ny8niQxdLAsk3ady/CGQlFqHTPKFfU5UASR2LRtYC1MCIvJHDFRKAp9kPJbQo9P37\nZ8IU7cDudkZFgNLmDixlWsh7C0ghX8fgAlj1P6FgsFufygam973k79GhIP54dELB\nc0S6E8ekkRSOXU9jX/IoiXuFglBvFihAdhvED58bMXzj2AwXUyeAlxItnvs+NVUC\nAwEAATANBgkqhkiG9w0BAQUFAAOBgQBkFZRbMoywK3hb0/X7MXmPYa7nlfnd5UXq\nr2n32ettzZNmEPaI2d1j+//nL5qqhOlrWPS88eKEPnBOX/jZpUWOuAAddnrvFzgw\nrp/C2H7oMT+29F+5ezeViLKbzoFYb4yECHBoi66IFXNae13yj7taMboBeUmE664G\nTB/MZpRr8g==\n-----END CERTIFICATE-----\n"
  PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0sOY9tHvVtLZ6xmVmH8d\n8LrRrNcWOXbrvvCrai+T3GtRvRSLhksLrpOpD0L9EHM6NdThNF/eGA9Oq+UKAe6y\nXR0hwsKuxKXqQ8SEmlhZZ9GiuggDB/zYD3ItB6SGpdkRe7kQqTChQyrIXqbRkJqx\noTXLyeJDF0sCyTdp3L8IZCUWodM8oV9TlQBJHYtG1gLUwIi8kcMVEoCn2Q8ltCj0\n/ftnwhTtwO52RkWA0uYOLGVayHsLSCFfx+ACWPU/oWCwW5/KBqb3veTv0aEg/nh0\nQsFzRLoTx6SRFI5dT2Nf8iiJe4WCUG8WKEB2G8QPnxsxfOPYDBdTJ4CXEi2e+z41\nVQIDAQAB\n-----END PUBLIC KEY-----\n"
  PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0sOY9tHvVtLZ6xmVmH8d8LrRrNcWOXbrvvCrai+T3GtRvRSL\nhksLrpOpD0L9EHM6NdThNF/eGA9Oq+UKAe6yXR0hwsKuxKXqQ8SEmlhZZ9GiuggD\nB/zYD3ItB6SGpdkRe7kQqTChQyrIXqbRkJqxoTXLyeJDF0sCyTdp3L8IZCUWodM8\noV9TlQBJHYtG1gLUwIi8kcMVEoCn2Q8ltCj0/ftnwhTtwO52RkWA0uYOLGVayHsL\nSCFfx+ACWPU/oWCwW5/KBqb3veTv0aEg/nh0QsFzRLoTx6SRFI5dT2Nf8iiJe4WC\nUG8WKEB2G8QPnxsxfOPYDBdTJ4CXEi2e+z41VQIDAQABAoIBAALhqbW2KQ+G0nPk\nZacwFbi01SkHx8YBWjfCEpXhEKRy0ytCnKW5YO+CFU2gHNWcva7+uhV9OgwaKXkw\nKHLeUJH1VADVqI4Htqw2g5mYm6BPvWnNsjzpuAp+BR+VoEGkNhj67r9hatMAQr0I\nitTvSH5rvd2EumYXIHKfz1K1SegUk1u1EL1RcMzRmZe4gDb6eNBs9Sg4im4ybTG6\npPIytA8vBQVWhjuAR2Tm+wZHiy0Az6Vu7c2mS07FSX6FO4E8SxWf8idaK9ijMGSq\nFvIS04mrY6XCPUPUC4qm1qNnhDPpOr7CpI2OO98SqGanStS5NFlSFXeXPpM280/u\nfZUA0AECgYEA+x7QUnffDrt7LK2cX6wbvn4mRnFxet7bJjrfWIHf+Rm0URikaNma\nh0/wNKpKBwIH+eHK/LslgzcplrqPytGGHLOG97Gyo5tGAzyLHUWBmsNkRksY2sPL\nuHq6pYWJNkqhnWGnIbmqCr0EWih82x/y4qxbJYpYqXMrit0wVf7yAgkCgYEA1twI\ngFaXqesetTPoEHSQSgC8S4D5/NkdriUXCYb06REcvo9IpFMuiOkVUYNN5d3MDNTP\nIdBicfmvfNELvBtXDomEUD8ls1UuoTIXRNGZ0VsZXu7OErXCK0JKNNyqRmOwcvYL\nJRqLfnlei5Ndo1lu286yL74c5rdTLs/nI2p4e+0CgYB079ZmcLeILrmfBoFI8+Y/\ngJLmPrFvXBOE6+lRV7kqUFPtZ6I3yQzyccETZTDvrnx0WjaiFavUPH27WMjY01S2\nTMtO0Iq1MPsbSrglO1as8MvjB9ldFcvp7gy4Q0Sv6XT0yqJ/S+vo8Df0m+H4UBpU\nf5o6EwBSd/UQxwtZIE0lsQKBgQCswfjX8Eg8KL/lJNpIOOE3j4XXE9ptksmJl2sB\njxDnQYoiMqVO808saHVquC/vTrpd6tKtNpehWwjeTFuqITWLi8jmmQ+gNTKsC9Gn\n1Pxf2Gb67PqnEpwQGln+TRtgQ5HBrdHiQIi+5am+gnw89pDrjjO5rZwhanAo6KPJ\n1zcPNQKBgQDxFu8v4frDmRNCVaZS4f1B6wTrcMrnibIDlnzrK9GG6Hz1U7dDv8s8\nNf4UmeMzDXjlPWZVOvS5+9HKJPdPj7/onv8B2m18+lcgTTDJBkza7R1mjL1Cje/Z\nKcVGsryKN6cjE7yCDasnA7R2rVBV/7NWeJV77bmzT5O//rW4yIfUIg==\n-----END RSA PRIVATE KEY-----\n"

  private

  class Router
    def initialize(routes)
      @routes = routes.map do |route, endpoint|
        pattern = Regexp.new("^#{route.gsub('*', '[^/]*')}$")
        [ pattern, endpoint ]
      end
    end

    attr_reader :routes
    attr_accessor :not_found

    def call(env)
      puts "#{env['REQUEST_METHOD']} #{env['PATH_INFO']}"
      clean_path = "/" + env['PATH_INFO'].split('/').select { |part| part != "" }.join("/")
      routes.each do |route, endpoint|
        if route.match(clean_path)
          return endpoint.call(env)
        end
      end
      not_found.call(env)
    end
  end

  class RestRequest
    def initialize(env)
      @env = env
    end

    attr_reader :env

    def base_uri
      @base_uri ||= "#{env['rack.url_scheme']}://#{env['HTTP_HOST']}#{env['SCRIPT_NAME']}"
    end

    def method
      @env['REQUEST_METHOD']
    end

    def rest_path
      @rest_path ||= env['PATH_INFO'].split('/').select { |part| part != "" }
    end

    def body=(body)
      @body = body
    end

    def body
      @body ||= env['rack.input'].read
    end

    def query_params
      @query_params ||= begin
        params = Rack::Request.new(env).GET
        params.keys.each do |key|
          params[key] = URI.unescape(params[key])
        end
        params
      end
    end
  end

  class RestBase
    def initialize(data)
      @data = data
    end

    attr_reader :data

    def call(env)
      begin
        rest_path = env['PATH_INFO'].split('/').select { |part| part != "" }
        method = env['REQUEST_METHOD'].downcase.to_sym
        if !self.respond_to?(method)
          return error(405, "Bad request method for '#{env['REQUEST_PATH']}': #{env['REQUEST_METHOD']}")
        end
        if !env['HTTP_ACCEPT'].split(';').include?('application/json')
          return [406, {"Content-Type" => "text/plain"}, "Must accept application/json"]
        end
        # Dispatch to get()/post()/put()/delete()
        begin
          self.send(method, RestRequest.new(env))
        rescue RestErrorResponse => e
          error(e.response_code, e.error)
        end
      rescue
        puts $!.inspect
        puts $!.backtrace
        raise
      end
    end

    def get_data(request, rest_path=nil)
      rest_path ||= request.rest_path
      # Grab the value we're looking for
      value = data
      rest_path.each do |path_part|
        if !value.has_key?(path_part)
          raise RestErrorResponse.new(404, "Object not found: #{build_uri(request.base_uri, rest_path)}")
        end
        value = value[path_part]
      end
      value
    end

    def error(response_code, error)
      json_response(response_code, {"error" => [error]})
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

    def populate_defaults(request, response)
      response
    end
  end

  class RestErrorResponse < Exception
    def initialize(response_code, error)
      @response_code = response_code
      @error = error
    end

    attr_reader :response_code
    attr_reader :error
  end

  class NotFoundEndpoint
    def call(env)
      return [404, {"Content-Type" => "application/json"}, "Object not found: #{env['REQUEST_PATH']}"]
    end
  end

  # Typical REST list endpoint (/roles or /data/BAG)
  class RestListEndpoint < RestBase
    def initialize(data, identity_key = 'name')
      super(data)
      @identity_key = identity_key
    end

    attr_reader :identity_key

    def get(request)
      # Get the result
      result_hash = {}
      get_data(request).keys.sort.each do |name|
        result_hash[name] = "#{build_uri(request.base_uri, request.rest_path + [name])}"
      end
      json_response(200, result_hash)
    end

    def post(request)
      container = get_data(request)
      contents = request.body
      key = JSON.parse(contents, :create_additions => false)[identity_key]
      if container[key]
        error(409, 'Object already exists')
      else
        container[key] = contents
        json_response(201, {'uri' => "#{build_uri(request.base_uri, request.rest_path + [key])}"})
      end
    end
  end

  # Typical REST leaf endpoint (/roles/NAME or /data/BAG/NAME)
  class RestObjectEndpoint < RestBase
    def initialize(data, identity_key = 'name')
      super(data)
      @identity_key = identity_key
    end

    attr_reader :identity_key

    def get(request)
      already_json_response(200, populate_defaults(request, get_data(request)))
    end

    def put(request)
      # We grab the old body to trigger a 404 if it doesn't exist
      old_body = get_data(request)
      request_json = JSON.parse(request.body, :create_additions => false)
      key = request_json[identity_key] || request.rest_path[-1]
      container = get_data(request, request.rest_path[0..-2])
      # If it's a rename, check for conflict and delete the old value
      rename = key != request.rest_path[-1]
      if rename
        if container.has_key?(key)
          return error(409, "Cannot rename '#{request.rest_path[0..-2]}' to '#{key}': '#{key}' already exists")
        end
        container.delete(request.rest_path[-1])
        container[key] = request.body
        already_json_response(201, populate_defaults(request, request.body))
      else
        container[key] = request.body
        already_json_response(200, populate_defaults(request, request.body))
      end
    end

    def delete(request)
      key = request.rest_path[-1]
      container = get_data(request, request.rest_path[0..-2])
      if !container.has_key?(key)
        raise RestErrorResponse.new(404, "Object not found: #{build_uri(request.base_uri, request.rest_path)}")
      end
      result = container[key]
      container.delete(key)
      already_json_response(200, populate_defaults(request, result))
    end

    def patch_request_body(request)
      container = get_data(request, request.rest_path[0..-2])
      existing_value = container[request.rest_path[-1]]
      if existing_value
        request_json = JSON.parse(request.body, :create_additions => false)
        existing_json = JSON.parse(existing_value, :create_additions => false)
        merged_json = existing_json.merge(request_json)
        if merged_json.size > request_json.size
          return JSON.pretty_generate(merged_json)
        end
      end
      request.body
    end
  end

  # /authenticate_user
  class AuthenticateUserEndpoint < RestBase
    def post(request)
      request_json = JSON.parse(request.body, :create_additions => false)
      name = request_json['name']
      password = request_json['password']
      user = data['users'][name]
      verified = user && JSON.parse(user, :create_additions => false)['password'] == password
      json_response(200, {
        'name' => name,
        'verified' => !!verified
      })
    end
  end

  # /clients or /users
  class ActorsEndpoint < RestListEndpoint
    def post(request)
      result = super(request)
      if result[0] == 201
        public_key = JSON.parse(request.body, :create_additions => false)['public_key']
        response = JSON.parse(result[2], :create_additions => false)
        response['public_key'] = public_key || PUBLIC_KEY
        response['private_key'] = PRIVATE_KEY unless public_key
        json_response(201, response)
      else
        result
      end
    end
  end

  # /clients/* and /users/*
  class ActorEndpoint < RestObjectEndpoint
    def put(request)
      # PUT /clients is patchy
      request.body = patch_request_body(request)

      # Honor private_key
      request_body = JSON.parse(request.body, :create_additions => false)
      gen_private_key = request_body['private_key']
      if request_body.has_key?('private_key')
        request_body.delete('private_key')
        if gen_private_key
          request_body.delete('public_key')
        end
        request.body = JSON.pretty_generate(request_body)
      end
      result = super(request)
      if result[0] == 200
        response = JSON.parse(result[2], :create_additions => false)
        response['private_key'] = PRIVATE_KEY if gen_private_key
        json_response(200, response)
      else
        result
      end
    end

    def populate_defaults(request, response)
      response_json = JSON.parse(response, :create_additions => false)
      response_json['name'] ||= request.rest_path[-1]
      response_json['admin'] ||= false
      response_json['public_key'] ||= PUBLIC_KEY
      if request.rest_path[0] == 'clients'
        response_json['validator'] ||= false
        response_json['json_class'] ||= "Chef::ApiClient"
        response_json['chef_type'] ||= "client"
      end
      JSON.pretty_generate(response_json)
    end
  end

  # /data
  class DataBagsEndpoint < RestListEndpoint
    def post(request)
      container = get_data(request)
      contents = request.body
      name = JSON.parse(contents, :create_additions => false)[identity_key]
      if container[name]
        error(409, "Object already exists")
      else
        container[name] = {}
        json_response(201, {"uri" => "#{build_uri(request.base_uri, request.rest_path + [name])}"})
      end
    end
  end

  # /data/NAME
  class DataBagEndpoint < RestListEndpoint
    def initialize(data)
      super(data, 'id')
    end

    def post(request)
      key = JSON.parse(request.body, :create_additions => false)[identity_key]
      response = super(request)
      if response[0] == 201
        already_json_response(201, DataBagItemEndpoint::populate_defaults(request, request.body, request.rest_path[1], key))
      else
        response
      end
    end

    def delete(request)
      key = request.rest_path[1]
      container = data['data']
      if !container.has_key?(key)
        raise RestErrorResponse.new(404, "Object not found: #{build_uri(request.base_uri, request.rest_path)}")
      end
      result = container[key]
      container.delete(key)
      json_response(200, {
        'chef_type' => 'data_bag',
        'json_class' => 'Chef::DataBag',
        'name' => key
      })
    end
  end

  # /data/NAME/NAME
  class DataBagItemEndpoint < RestObjectEndpoint
    def initialize(data)
      super(data, 'id')
    end

    def populate_defaults(request, response)
      DataBagItemEndpoint::populate_defaults(request, response, request.rest_path[1], request.rest_path[2])
    end

    def self.populate_defaults(request, response, data_bag, data_bag_item)
      response_json = JSON.parse(response, :create_additions => false)
      if request.method == 'DELETE'
        # TODO SERIOUSLY, WHO DOES THIS MANY EXCEPTIONS IN THEIR INTERFACE
        if !(response_json['json_class'] == 'Chef::DataBagItem' && response_json['raw_data'])
          response_json = { 'raw_data' => response_json }
          response_json['chef_type'] ||= 'data_bag_item'
          response_json['json_class'] ||= 'Chef::DataBagItem'
          response_json['data_bag'] ||= data_bag
          response_json['name'] ||= "data_bag_item_#{data_bag}_#{data_bag_item}"
        end
      else
        # If it's not already wrapped with raw_data, wrap it.
        if response_json['json_class'] == 'Chef::DataBagItem' && response_json['raw_data']
          response_json = response_json['raw_data']
        end
        # Argh.  We don't do this on GET, but we do on PUT and POST????
        if %w(PUT POST).include?(request.method)
          response_json['chef_type'] ||= 'data_bag_item'
          response_json['data_bag'] ||= data_bag
        end
        response_json['id'] ||= data_bag_item
      end
      JSON.pretty_generate(response_json)
    end
  end

  # /environments/NAME
  class EnvironmentEndpoint < RestObjectEndpoint
    def delete(request)
      if request.rest_path[1] == "_default"
        # 405, really?
        error(405, "The '_default' environment cannot be modified.")
      else
        super(request)
      end
    end

    def put(request)
      if request.rest_path[1] == "_default"
        # 404, 405 ... can we *decide* on an error code, please?
        error(404, "The '_default' environment cannot be modified.")
      else
        super(request)
      end
    end

    def populate_defaults(request, response)
      response_json = JSON.parse(response, :create_additions => false)
      response_json['name'] ||= request.rest_path[-1]
      response_json['description'] ||= ''
      response_json['cookbook_versions'] ||= {}
      response_json['json_class'] ||= "Chef::Environment"
      response_json['chef_type'] ||= "environment"
      response_json['default_attributes'] ||= {}
      response_json['override_attributes'] ||= {}
      JSON.pretty_generate(response_json)
    end
  end

  # /sandboxes
  class SandboxesEndpoint < RestBase
    def initialize(data)
      super(data)
      @next_id = 1
    end

    def post(request)
      sandbox_checksums = []

      needed_checksums = JSON.parse(request.body, :create_additions => false)['checksums']
      result_checksums = {}
      needed_checksums.keys.each do |needed_checksum|
        if data['file_store'].has_key?(needed_checksum)
          result_checksums[needed_checksum] = { :needs_upload => false }
        else
          result_checksums[needed_checksum] = {
            :needs_upload => true,
            :url => build_uri(request.base_uri, ['file_store', needed_checksum])
          }
          sandbox_checksums << needed_checksum
        end
      end

      id = @next_id.to_s
      @next_id+=1

      data['sandboxes'][id] = sandbox_checksums

      json_response(201, {
        :uri => build_uri(request.base_uri, request.rest_path + [id.to_s]),
        :checksums => result_checksums,
        :sandbox_id => id
      })
    end
  end

  # /sandboxes/ID
  class SandboxEndpoint < RestBase
    def put(request)
      existing_sandbox = get_data(request, request.rest_path)
      data['sandboxes'].delete(request.rest_path[1])
      json_response(200, {
        :guid => request.rest_path[1],
        :name => request.rest_path[1],
        :checksums => existing_sandbox,
#        :create_time => TODO ???
        :is_completed => true
      })
    end
  end

  # The minimum amount of S3 necessary to support cookbook upload/download
  # /file_store/FILE
  class FileStoreFileEndpoint < RestBase
    def get(request)
      [200, {"Content-Type" => 'application/x-binary'}, get_data(request) ]
    end

    def put(request)
      data['file_store'][request.rest_path[1]] = request.body
      json_response(200, {})
    end
  end

  # Common code for endpoints that return cookbook lists
  class CookbooksBase < RestBase
    def format_cookbooks_list(request, cookbooks_list, constraints = {}, num_versions = nil)
      results = {}
      cookbooks_list.keys.sort.each do |name|
        constraint = Chef::VersionConstraint.new(constraints[name])
        versions = []
        cookbooks_list[name].keys.sort_by { |version| Chef::Version.new(version) }.reverse.each do |version|
          break if num_versions && versions.size >= num_versions
          if constraint.include?(version)
            versions << {
              'url' => build_uri(request.base_uri, ['cookbooks', name, version]),
              'version' => version
            }
          end
        end
        results[name] = {
          'url' => build_uri(request.base_uri, ['cookbooks', name]),
          'versions' => versions
        }
      end
      results
    end
  end

  # /cookbooks
  class CookbooksEndpoint < CookbooksBase
    def get(request)
      json_response(200, format_cookbooks_list(request, data['cookbooks']))
    end
  end

  # /cookbooks/NAME
  class CookbookEndpoint < CookbooksBase
    def get(request)
      filter = request.rest_path[1]
      case filter
      when '_latest'
        result = {}
        data['cookbooks'].each_pair do |name, versions|
          result[name] = build_uri(request.base_uri, ['cookbooks', name, latest_version(versions.keys)])
        end
        json_response(200, result)
      when '_recipes'
        result = []
        data['cookbooks'].each_pair do |name, versions|
          latest = JSON.parse(versions[latest_version(versions.keys)], :create_additions => false)
          if latest['recipes']
            latest['recipes'].each do |recipe|
              if recipe['path'] == "recipes/#{recipe['name']}" && recipe['name'][-3..-1] == '.rb'
                result << "#{name}::#{recipe['name'][0..-4]}"
              end
            end
          end
        end
        json_response(200, result.sort)
      else
        cookbook_list = { filter => get_data(request, request.rest_path) }
        json_response(200, format_cookbooks_list(request, cookbook_list))
      end
    end

    def latest_version(versions)
      sorted = versions.sort_by { |version| Chef::Version.new(version) }
      sorted[-1]
    end
  end

  # /cookbooks/NAME/VERSION
  class CookbookVersionEndpoint < RestObjectEndpoint
    def get(request)
      if request.rest_path[2] == "_latest"
        request.rest_path[2] = latest_version(get_data(request, request.rest_path[0..1]).keys)
      end
      super(request)
    end

    def put(request)
      name = request.rest_path[1]
      version = request.rest_path[2]
      data['cookbooks'][name] = {} if !data['cookbooks'][name]
      existing_cookbook = data['cookbooks'][name][version]

      # Honor frozen
      if existing_cookbook
        existing_cookbook_json = JSON.parse(existing_cookbook, :create_additions => false)
        if existing_cookbook_json['frozen?']
          if request.query_params['force'] != "true"
            raise RestErrorResponse.new(409, "The cookbook #{name} at version #{version} is frozen. Use the 'force' option to override.")
          end
          # For some reason, you are forever unable to modify "frozen?" on a frozen cookbook.
          request_json = JSON.parse(request.body, :create_additions => false)
          if !request_json['frozen?']
            request_json['frozen?'] = true
            request.body = JSON.pretty_generate(request_json)
          end
        end
      end

      # Set the cookbook
      data['cookbooks'][name][version] = request.body

      # If the cookbook was updated, check for deleted files and clean them up
      if existing_cookbook
        missing_checksums = get_checksums(existing_cookbook) - get_checksums(request.body)
        if missing_checksums.size > 0
          hoover_unused_checksums(missing_checksums)
        end
      end

      already_json_response(existing_cookbook ? 200 : 201, populate_defaults(request, data['cookbooks'][name][version]))
    end

    def delete(request)
      deleted_cookbook = get_data(request, request.rest_path)
      response = super(request)
      cookbook_name = request.rest_path[1]
      data['cookbooks'].delete(cookbook_name) if data['cookbooks'][cookbook_name].size == 0

      # Hoover deleted files, if they exist
      hoover_unused_checksums(get_checksums(deleted_cookbook))
      response
    end

    def get_checksums(cookbook)
      result = []
      JSON.parse(cookbook, :create_additions => false).each_pair do |key, value|
        if value.is_a?(Array)
          value.each do |file|
            if file.is_a?(Hash) && file.has_key?('checksum')
              result << file['checksum']
            end
          end
        end
      end
      result
    end

    def hoover_unused_checksums(deleted_checksums)
      data['cookbooks'].each_pair do |cookbook_name, versions|
        versions.each_pair do |cookbook_version, cookbook|
          deleted_checksums = deleted_checksums - get_checksums(cookbook)
        end
      end
      deleted_checksums.each do |checksum|
        data['file_store'].delete(checksum)
      end
    end

    def populate_defaults(request, response)
      # Inject URIs into each cookbook file
      cookbook = JSON.parse(response, :create_additions => false)
      cookbook.each_pair do |key, value|
        if value.is_a?(Array)
          value.each do |file|
            if file.is_a?(Hash) && file.has_key?('checksum')
              file['url'] ||= build_uri(request.base_uri, ['file_store', file['checksum']])
            end
          end
        end
      end
      cookbook['name'] ||= "#{request.rest_path[-2]}-#{request.rest_path[-1]}"
      cookbook['version'] ||= request.rest_path[-1]
      cookbook['cookbook_name'] ||= request.rest_path[-2]
      cookbook['json_class'] ||= 'Chef::CookbookVersion'
      cookbook['chef_type'] ||= 'cookbook_version'
      cookbook['frozen?'] ||= false
      cookbook['metadata'] ||= {}
      cookbook['metadata']['version'] ||= request.rest_path[-1]
      cookbook['metadata']['name'] ||= request.rest_path[-2]
      JSON.pretty_generate(cookbook)
    end

    def latest_version(versions)
      sorted = versions.sort_by { |version| Chef::Version.new(version) }
      sorted[-1]
    end
  end

  # /environments/NAME/cookbooks
  class EnvironmentCookbooksEndpoint < CookbooksBase
    def get(request)
      environment = JSON.parse(get_data(request, request.rest_path[0..1]), :create_additions => false)
      constraints = environment['cookbook_versions']
      if request.query_params['num_versions'] == 'all'
        num_versions = nil
      elsif request.query_params['num_versions']
        num_versions = request.query_params['num_versions'].to_i
      else
        num_versions = 1
      end
      json_response(200, format_cookbooks_list(request, data['cookbooks'], constraints, num_versions))
    end
  end

  # /environments/NAME/cookbooks/NAME
  class EnvironmentCookbookEndpoint < CookbooksBase
    def get(request)
      cookbook_name = request.rest_path[3]
      environment = JSON.parse(get_data(request, request.rest_path[0..1]), :create_additions => false)
      constraints = environment['cookbook_versions']
      json_response(200, format_cookbooks_list(request, { cookbook_name => data['cookbooks'][cookbook_name] }, constraints))
    end
  end

  # /environments/NAME/cookbook_versions
  class EnvironmentCookbookVersionsEndpoint < RestBase
    def cookbooks
      data['cookbooks']
    end

    def environments
      data['environments']
    end

    def post(request)
      # Get the list of cookbooks and versions desired by the runlist
      desired_versions = {}
      run_list = JSON.parse(request.body, :create_additions => false)['run_list']
      run_list.each do |run_list_entry|
        if run_list_entry =~ /(.+)\@(.+)/
          raise RestErrorResponse.new(412, "No such cookbook: #{$1}") if !cookbooks[$1]
          raise RestErrorResponse.new(412, "No such cookbook version for cookbook #{$1}: #{$2}") if !cookbooks[$1][$2]
          desired_versions[$1] = [ $2 ]
        else
          raise RestErrorResponse.new(412, "No such cookbook: #{run_list_entry}") if !cookbooks[run_list_entry]
          desired_versions[run_list_entry] = cookbooks[run_list_entry].keys
        end
      end

      # Filter by environment constraints
      environment = JSON.parse(get_data(request, request.rest_path[0..1]), :create_additions => false)
      environment_constraints = environment['cookbook_versions']

      desired_versions.each_key do |name|
        desired_versions = filter_by_constraint(desired_versions, name, environment_constraints[name])
      end

      # Depsolve!
      solved = depsolve(desired_versions.keys, desired_versions, environment_constraints)
      if !solved
        return raise RestErrorResponse.new(412, "Unsolvable versions!")
      end

      result = {}
      solved.each_pair do |name, versions|
        result[name] = JSON.parse(data['cookbooks'][name][versions[0]], :create_additions => false)
      end
      json_response(200, result)
    end

    def depsolve(unsolved, desired_versions, environment_constraints)
      return nil if desired_versions.values.any? { |versions| versions.empty? }

      # If everything is already
      solve_for = unsolved[0]
      return desired_versions if !solve_for

      # Go through each desired version of this cookbook, starting with the latest,
      # until we find one we can solve successfully with
      sort_versions(desired_versions[solve_for]).each do |desired_version|
        new_desired_versions = desired_versions.clone
        new_desired_versions[solve_for] = [ desired_version ]
        new_unsolved = unsolved[1..-1]

        # Pick this cookbook, and add dependencies
        cookbook_obj = JSON.parse(cookbooks[solve_for][desired_version], :create_additions => false)
        dep_not_found = false
        cookbook_obj['metadata']['dependencies'].each_pair do |dep_name, dep_constraint|
          # If the dep is not already in the list, add it to the list to solve
          # and bring in all environment-allowed cookbook versions to desired_versions
          if !new_desired_versions.has_key?(dep_name)
            new_unsolved = new_unsolved + [dep_name]
            # If the dep is missing, we will try other versions of the cookbook that might not have the bad dep.
            if !cookbooks[dep_name]
              dep_not_found = true
              break
            end
            new_desired_versions[dep_name] = cookbooks[dep_name].keys
            new_desired_versions = filter_by_constraint(new_desired_versions, dep_name, environment_constraints[dep_name])
          end
          new_desired_versions = filter_by_constraint(new_desired_versions, dep_name, dep_constraint)
        end

        next if dep_not_found

        # Depsolve children with this desired version!  First solution wins.
        result = depsolve(new_unsolved, new_desired_versions, environment_constraints)
        return result if result
      end
      return nil
    end

    def sort_versions(versions)
      result = versions.sort_by { |version| Chef::Version.new(version) }
      result.reverse
    end

    def filter_by_constraint(versions, cookbook_name, constraint)
      return versions if !constraint
      constraint = Chef::VersionConstraint.new(constraint)
      new_versions = versions[cookbook_name]
      new_versions = new_versions.select { |version| constraint.include?(version) }
      result = versions.clone
      result[cookbook_name] = new_versions
      result
    end
  end

  # /environment/NAME/nodes
  class EnvironmentNodesEndpoint < RestBase
    def get(request)
      # 404 if environment does not exist
      get_data(request, request.rest_path[0..1])

      result = {}
      data['nodes'].each_pair do |name, node|
        node_json = JSON.parse(node, :create_additions => false)
        if node['chef_environment'] == request.rest_path[1]
          result[name] = build_uri(request.base_uri, 'nodes', name)
        end
      end
      json_response(200, result)
    end
  end
end

require 'tiny_chef_server_search'

server = TinyChefServer.new(:Port => 8889)
server.start
