require 'openssl'

module SSLChecker
  # Utility for parsing X509 certificates
  module X509
    # Checks if a X509 certificate is expired
    class ExpirationChecker
      ##
      # Takes a X509 certificate encoded in Base64 (PEM) and
      # evaluates if it is expired in relation to given date.
      #
      # @param certificate [String] Base64 encoded PEM certificate.
      # @param date [DateTime] Date to evaluate certificate against.
      # @return [Boolean] True if certificate expiration is earlier
      #                   than given date. False if certificate
      #                   expiration is later than given date.
      #
      def self.expired?(certificate, date)
        cert = OpenSSL::X509::Certificate.new(certificate)
        cert.not_after.to_datetime < date
      end
    end
  end
end
