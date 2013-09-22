require "open-uri"
module Virustotal
  class Client

    attr_accessor :options


    def self.file_scan(file_path_or_uri)
      options.merge!({ file: open( file_path_or_uri ) })
      RestClient.post endpoint("/file/scan"), options
    end

    def self.file_rescan()
    end

    def self.file_report()
    end

    def self.url_scan(url)
      options.merge!({ url: url })
      RestClient.post endpoint("/url/scan"), options
    end

    def self.url_report(url_or_scan_id)
      options.merge!({ resource: url_or_scan_id })
      RestClient.post endpoint("/url/report"), options
    end

    def self.ip_adress_report()
    end

    def self.domain_report()
    end

    def self.comments_put
    end

    private
    def self.options
      @options ||= { apikey: Virustotal::API.api_key }
    end

    def self.endpoint(path)
      Virustotal::API.base_uri + path
    end
  end
end