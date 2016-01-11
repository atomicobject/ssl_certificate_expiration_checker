require 'net/http'
require 'logger'

module SSLChecker
  # DeadMan's Snitch notifier
  class SnitchNotifier
    attr_accessor :logger
    attr_reader :http

    ##
    # Initializes a DeadMan's Snitch notifier on the
    # specified host and port.
    #
    # @param host [String] FQDN or IP address of host to notify.
    # @param port [Integer] TCP port number of host to notify.
    def initialize(host = 'nosnch.in', port = 443)
      @logger = Logger.new(STDOUT)
      logger.level = Logger::INFO
      @http = Net::HTTP.new(host, port)
      @http.use_ssl = true
    end

    ##
    # Notifies a DeadMan's Snitch via HTTP Get request.
    #
    # @param id [String] ID of snitch to notify.
    # @return [Boolean] True if snitch is successfully notified,
    #                   false otherwise.
    #
    def notify(id)
      logger.info("Notifying snitch #{id}")
      result = http.get('/' + id)
      logger.debug("Snitch notification result: #{result}")
      result.is_a? Net::HTTPSuccess
    end

    private

    attr_writer :http
  end
end
