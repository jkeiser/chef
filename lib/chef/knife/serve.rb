require 'chef/chef_fs/knife'

class Chef
  class Knife
    class Serve < Chef::ChefFS::Knife
      banner "knife show [PATTERN1 ... PATTERNn]"

      deps do
        begin
          require 'chef_zero/server'
        rescue LoadError
          STDERR.puts <<EOM
ERROR: chef-zero must be installed to run "knife serve"!  To install:

    gem install chef-zero

EOM
          exit(1)
        end
        require 'chef/chef_fs/chef_fs_data_store'
      end

      option :remote,
        :long => '--remote',
        :boolean => true,
        :description => "Proxy the remote server instead of the local filesystem"

      option :host,
        :short => '-H',
        :long => '--host=HOST',
        :description => "Host to bind to (default: 127.0.0.1)"

      option :port,
        :short => '-p',
        :long => '--port=PORT',
        :description => "Port to listen on (default: 4000)"

      option :generate_real_keys,
        :long => '--[no-]generate-keys',
        :boolean => true,
        :description => "Whether to generate actual keys or fake it (faster).  Default: false."

      def run
        server_options = {}
        server_options[:data_store] = ChefFSDataStore.new(proc { config[:remote] ? create_chef_fs : create_local_fs })
        server_options[:log_level] = Chef::Log.level
        server_options[:host] = config[:host] if config[:host]
        server_options[:port] = config[:port] ? config[:port].to_i : 4000
        server_options[:generate_real_keys] = config[:generate_real_keys] if config[:generate_real_keys]

        ChefZero::Server.new(server_options).start(:publish => true)
      end
    end
  end
end
