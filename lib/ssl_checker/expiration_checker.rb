require 'date'
require 'logger'

module SSLChecker
  # Checks if a SSL Certificate is expired
  class ExpirationChecker
    attr_accessor :logger
    attr_reader :deadline, :notifier

    # Initializes an ExpirationChecker, with the specified deadline.
    #
    # @param deadline [DateTime] The date to use when evaluating
    #                            certificates for expiration.
    def initialize(deadline = DateTime.now)
      @logger = Logger.new(STDOUT)
      logger.level = Logger::INFO
      @deadline = deadline
      @notifier = SnitchNotifier.new
    end

    # Checks the certificate for the specified host and port.
    #
    # @param host [String] The FQDN or IP address of the host to check.
    # @param port [Integer] The TCP port number of the host to check.
    # @return [Boolean] False if the certificate is expired, and true
    #                   if it has not.
    def check(host, port)
      logger.debug("Deadline threshold: #{deadline}")
      begin
        cert = X509::Retriever.retrieve(host, port)
      rescue
        logger.error("Could not open TCPSocket to #{host}:#{port}. " \
                     'Are the hostname and port correct?')
        return false
      end
      if X509::ExpirationChecker.expired?(cert, deadline)
        logger.error("Certificate for #{host} is expired.")
        return false
      else
        logger.info("Certificate for #{host} is within expiry.")
        return true
      end
    end

    # Checks the certificate for the specified host and port, and
    # notifies the specified snitch.
    #
    # @param host [String] The FQDN or IP address of the host to check.
    # @param port [Integer] The TCP port number of the host to check.
    # @param snitch [String] The ID of the snitch to notify.
    # @return [Boolean] False if the certificate is expired, or if
    #                   notifying the snitch has failed, and true
    #                   otherwise.
    def check_and_notify(host, port, snitch)
      logger.debug("Deadline threshold: #{deadline}")
      begin
        cert = X509::Retriever.retrieve(host, port)
      rescue
        logger.error("Could not open TCPSocket to #{host}:#{port}. " \
                     'Are the hostname and port correct?')
        return false
      end
      if X509::ExpirationChecker.expired?(cert, deadline)
        logger.error("Certificate for #{host} is expired.")
        return false
      else
        logger.info("Certificate for #{host} is within expiry.")
        notify(snitch)
      end
    end

    private

    def notify(snitch)
      result = notifier.notify(snitch)
      logger.info("Notifying snitch #{snitch} succeeded.") if result
      logger.error("Notifying snitch #{snitch} failed.") unless result
      result
    end

    attr_writer :notifier
  end
end
