require "open-uri"
module Virustotal
  class Client

    # Sending and scanning files
    def self.file_scan(file_path_or_uri)
      options.merge!({ file: open( file_path_or_uri ) })
      RestClient.post endpoint("/file/scan"), options
    end

    # Rescanning already submitted files
    def self.file_rescan(resources)
      resources = format(resources)
      options.merge!({ resource: resources})
      RestClient.post endpoint("/file/rescan"), options
    end

    # Retrieving file scan reports
    def self.file_report(resources)
      resources = format(resources)
      options.merge!({ resource: resources })
      RestClient.post endpoint("/file/report"), options
    end

    # Sending and scanning URLs
    def self.url_scan(url)
      options.merge!({ url: url })
      RestClient.post endpoint("/url/scan"), options
    end

    # Retrieving URL scan reports
    def self.url_report(resource) # resource: scan_id or url
      options.merge!({ resource: resource })
      RestClient.post endpoint("/url/report"), options
    end

    # Retrieving IP address reports
    def self.ip_adress_report(ip_adress)
      options.merge!({ ip: ip_adress })
      RestClient.get endpoint("/ip-address/report"), params: options
    end

    # Retrieving domain reports
    def self.domain_report(domain)
      options.merge!({ domain: domain})
      RestClient.get endpoint("/domain/report"), params: options
    end

    # Make comments on files and URLs
    def self.comments_put(resource, comment)
      options.merge!({ resource: resource, comment: comment })
      RestClient.post endpoint("/comments/put"), options
    end

    private
    def self.options
      @options ||= { apikey: Virustotal::API.api_key }
    end

    def self.endpoint(path)
      Virustotal::API.base_uri + path
    end

    def format(resources)
      resources.class == Array ? resources.join(", ") : resources
    end
  end
end