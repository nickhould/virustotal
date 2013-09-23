require "open-uri"
require "json"

module Virustotal
  class Client

    attr_accessor :api_key, :user_agent

    def initialize(options={})
      for key, value in options
        send(:"#{key}=", value)
      end
      yield self if block_given?
      validate_credentials_type!
    end

    # Configuration
    def self.api_key
      instance_variable_defined?(:@api_key) ? @api_key : ENV["virustotal_api_key"]
    end

    def self.user_agent
      @user_agent ||= "VirusTotal Ruby Gem #{Virustotal::VERSION}"
    end

    # Requests
    # Sending and scanning files
    def file_scan(file_path_or_uri)
      merged_options = options.merge({ file: open( file_path_or_uri ) })
      response = RestClient.post endpoint("/file/scan"), merged_options
      JSON.parse response
    end

    # Rescanning already submitted files
    def file_rescan(resources)
      resources = format(resources)
      merged_options = options.merge({ resource: resources})
      response = RestClient.post endpoint("/file/rescan"), merged_options
      JSON.parse response
    end

    # Retrieving file scan reports
    def file_report(resources)
      resources = format(resources)
      merged_options = options.merge({ resource: resources })
      response = RestClient.post endpoint("/file/report"), merged_options
      JSON.parse response
    end

    # Sending and scanning URLs
    def url_scan(url)
      merged_options = options.merge({ url: url })
      response = RestClient.post endpoint("/url/scan"), merged_options
      JSON.parse response
    end

    # Retrieving URL scan reports
    def url_report(resource) # resource: scan_id or url
      merged_options = options.merge!({ resource: resource })
      response = RestClient.post endpoint("/url/report"), merged_options
      JSON.parse response
    end

    # Retrieving IP address reports
    def ip_adress_report(ip_adress)
      merged_options = options.merge({ ip: ip_adress })
      response = RestClient.get endpoint("/ip-address/report"), params: merged_options
      JSON.parse response
    end

    # Retrieving domain reports
    def domain_report(domain)
      merged_options = options.merge({ domain: domain})
      response = RestClient.get endpoint("/domain/report"), params: merged_options
      JSON.parse response
    end

    # Make comments on files and URLs
    def comments_put(resource, comment)
      merged_options = options.merge({ resource: resource, comment: comment })
      response = RestClient.post endpoint("/comments/put"), merged_options
      JSON.parse response
    end

    private
    def options
      @options ||= { apikey: api_key, user_agent: user_agent }
    end

    def endpoint(path)
      Virustotal::API::ENDPOINT + path
    end

    def format(resources)
      resources.class == Array ? resources.join(", ") : resources
    end

    def validate_credentials_type!
      raise(InvalidCredentials, "Invalid API key. Must be a string.") if !api_key.nil? && !api_key.is_a?(String)
    end
  end
end