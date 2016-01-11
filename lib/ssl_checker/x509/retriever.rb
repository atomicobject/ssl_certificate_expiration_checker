require 'socket'
require 'openssl'
require 'logger'

module SSLChecker
  # Utility for parsing X509 certificates
  module X509
    # Retrieves a x509 certificate
    class Retriever
      @logger ||= Logger.new(STDOUT)
      @logger.level = Logger::ERROR

      # Retrieves the X509 certificate from a specified host and
      # port.
      #
      # @param host [String] FQDN or IP address of host to use.
      # @param port [Integer] TCP port number of host to use.
      # @return [String] The Base64 encoded PEM certificate.
      #
      def self.retrieve(host, port)
        @logger.debug("Opening TCPSocket to #{host}:#{port}")
        tcp_socket = TCPSocket.new(host, port)
        @logger.debug("Opening SSLSocket to #{host}:#{port}")
        ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket)
        ssl_socket.connect
        cert = ssl_socket.peer_cert
        @logger.debug("Got peer_cert:\n#{cert}")
        ssl_socket.sysclose
        tcp_socket.close
        cert
      end
    end
  end
end
