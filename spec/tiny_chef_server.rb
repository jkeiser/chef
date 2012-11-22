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
        'clients' => RestListEndpoint.new(server.data[:clients], 'name'),
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
