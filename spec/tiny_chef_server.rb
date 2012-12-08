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
        'chef-validator' => TinyChefServer::make_client('chef-validator', true, false),
        'chef-webui' => TinyChefServer::make_client('chef-webui', false, true)
      },
      'cookbooks' => {},
      'data' => {},
      'environments' => {
        "_default" => DEFAULT_ENVIRONMENT
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
        [ '/data/*', RestListEndpoint.new(data, 'id') ],
        [ '/data/*/*', RestObjectEndpoint.new(data, 'id') ],
        [ '/environments', RestListEndpoint.new(data) ],
        [ '/environments/*', EnvironmentEndpoint.new(data) ],
        [ '/environments/*/cookbooks', EnvironmentCookbooksEndpoint.new(data) ],
        [ '/environments/*/cookbooks/*', EnvironmentCookbookEndpoint.new(data) ],
        [ '/environments/*/cookbook_versions', EnvironmentCookbookVersionsEndpoint.new(data) ],
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

  DEFAULT_ENVIRONMENT = <<EOM
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

  def self.make_client(clientname, validator, admin)
    result = <<EOM
{
  "clientname": "#{clientname}",
  "name": "#{clientname}",
  "certificate": #{PUBLIC_KEY.inspect},
  "validator": #{validator},
  "admin": #{admin}
}
EOM
    result
  end

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
          return error(400, "Bad request method for '#{env['REQUEST_PATH']}': #{env['REQUEST_METHOD']}")
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
      name = JSON.parse(contents, :create_additions => false)[identity_key]
      if container[name]
        error(409, "Object already exists")
      else
        container[name] = contents
        json_response(201, {"uri" => "#{build_uri(request.base_uri, request.rest_path + [name])}"})
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
      already_json_response(200, get_data(request))
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
      end
      container[key] = request.body
      already_json_response(rename ? 201 : 200, request.body)
    end
    def delete(request)
      key = request.rest_path[-1]
      container = get_data(request, request.rest_path[0..-2])
      if !container.has_key?(key)
        raise RestErrorResponse.new(404, "Object not found: #{build_uri(request.base_uri, request.rest_path)}")
      end
      result = container[key]
      container.delete(key)
      already_json_response(200, result)
    end
  end

  # /authenticate_user
  class AuthenticateUserEndpoint < RestBase
    def post(request)
      request_json = JSON.parse(request.body, :create_additions => false)
      name = request_json["name"]
      password = request_json["password"]
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
        response["public_key"] = public_key || PUBLIC_KEY
        response["private_key"] = PRIVATE_KEY unless public_key
        json_response(201, response)
      else
        result
      end
    end
  end

  # /clients/* and /users/*
  class ActorEndpoint < RestObjectEndpoint
    def get(request)
      result = super(request)
      if result[0] == 200
        response = JSON.parse(result[2], :create_additions => false)
        response['public_key'] ||= PUBLIC_KEY
        json_response(200, response)
      else
        result
      end
    end

    def put(request)
      request_body = JSON.parse(request.body, :create_additions => false)
      gen_private_key = request_body['private_key']
      if gen_private_key
        request_body.delete('private_key')
        request.body = JSON.pretty_generate(request_body)
      end
      result = super(request)
      if result[0] == 200
        response = JSON.parse(result[2], :create_additions => false)
        response['private_key'] = PRIVATE_KEY if gen_private_key
        response['public_key'] ||= PUBLIC_KEY
        json_response(200, response)
      else
        result
      end
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

  # /environments/NAME
  class EnvironmentEndpoint < RestObjectEndpoint
    def delete(request)
      if request.rest_path[1] == "_default"
        error(403, "_default environment cannot be modified")
      else
        super(request)
      end
    end
    def put(request)
      if request.rest_path[1] == "_default"
        error(403, "_default environment cannot be modified")
      else
        super(request)
      end
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
      data['sandboxes'].delete(request.rest_path[1])
      json_response(200, { :sandbox_id => request.rest_path[1]})
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
    def format_cookbooks_list(request, cookbooks_list, constraints = {})
      results = {}
      cookbooks_list.keys.sort.each do |name|
        constraint = Chef::VersionConstraint.new(constraints[name])
        versions = {}
        cookbooks_list[name].keys.sort.each do |version|
          if constraint.include?(version)
            versions[version] = {
              'url' => build_uri(request.base_uri, ['cookbooks', name, version]),
              'version' => version
            }
          end
        end
        if versions.size > 0
          results[name] = {
            'url' => build_uri(request.base_uri, ['cookbooks', name]),
            'versions' => versions
          }
        end
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
      name = request.rest_path[1]
      json_response(200, format_cookbooks_list(request, { name => data['cookbooks'][name] }))
    end
  end

  # /cookbooks/NAME/VERSION
  class CookbookVersionEndpoint < RestObjectEndpoint
    def get(request)
      if request.rest_path[2] == "_latest"
        sorted_versions = data['cookbooks'][request.rest_path[1]].keys.sort_by { |version| Chef::Version.new(version) }
        request.rest_path[2] = sorted_versions[-1]
      end
      super(request)
    end

    def put(request)
      name = request.rest_path[1]
      version = request.rest_path[2]
      data['cookbooks'][name] = {} if !data['cookbooks'][name]
      response_code = data['cookbooks'][name][version] ? 200 : 201
      data['cookbooks'][name][version] = request.body
      already_json_response(response_code, data['cookbooks'][name][version])
    end

    def delete(request)
      response = super(request)
      cookbook_name = request.rest_path[1]
      data['cookbooks'].delete(cookbook_name) if data['cookbooks'][cookbook_name].size == 0
      response
    end
  end

  # /environments/NAME/cookbooks
  class EnvironmentCookbooksEndpoint < CookbooksBase
    def get(request)
      environment = JSON.parse(get_data(request, request.rest_path[0..1]), :create_additions => false)
      constraints = environment['cookbook_versions']
      json_response(200, format_cookbooks_list(request, data['cookbooks'], constraints))
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
          error(400, "No such cookbook: #{$1}") if !cookbooks[$1]
          error(400, "No such cookbook version for cookbook #{$1}: #{$2}") if !cookbooks[$1][$2]
          desired_versions[$1] = [ $2 ]
        else
          error(400, "No such cookbook: #{run_list_entry}") if !cookbooks[run_list_entry]
          desired_versions[run_list_entry] = cookbooks[run_list_entry].keys
        end
      end

      # Filter by environment constraints
      environment_name = request.rest_path[1]
      environment = JSON.parse(environments[environment_name], :create_additions => false)
      environment_constraints = environment['cookbook_versions']

      desired_versions.each_key do |name|
        desired_versions = filter_by_constraint(desired_versions, name, environment_constraints[name])
      end

      # Depsolve!
      solved = depsolve(desired_versions.keys, desired_versions, environment_constraints)
      if !solved
        return error(400, "Unsolvable versions!")
      end

      result = {}
      solved.each_pair do |name, versions|
        result[name] = versions[0]
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
        cookbook_obj['metadata']['dependencies'].each_pair do |dep_name, dep_constraint|
          # If the dep is not already in the list, add it to the list to solve
          # and bring in all environment-allowed cookbook versions to desired_versions
          if !new_desired_versions.has_key?(dep_name)
            new_unsolved = new_unsolved + [dep_name]
            new_desired_versions[dep_name] = cookbooks[dep_name].keys
            new_desired_versions = filter_by_constraint(new_desired_versions, dep_name, environment_constraints[dep_name])
          end
          new_desired_versions = filter_by_constraint(new_desired_versions, dep_name, dep_constraint)
        end

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
end

require 'tiny_chef_server_search'

server = TinyChefServer.new(:Port => 8889)
server.start
