require 'spec_helper'

describe 'x509 expiration validator' do
  let(:validator) { ::SSLChecker::X509::ExpirationChecker }

  # Self-signed certificate with expiry on 4 April 2016
  certificate = <<-EOF
-----BEGIN CERTIFICATE-----
MIIDtTCCAp2gAwIBAgIJAOQ8OYAdaEDpMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTUwNDA1MDAwNzIxWhcNMTYwNDA0MDAwNzIxWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAw3mL6PXgPO0XdG7QzjkZ+eNmwwrW2b/bAvsswNeY+F3NzrdjOc3Duem3
2QRzm280Fst/CiDqxILv8yUk+cadQHMe3TOSD22Tl8n4qX4XKZVg9xe+mTP38cCf
5ratGFGBmSD1huT3mJ2ZeDywxHRgL5AIA1G4F8UgTfvCV2P3+OG10ZoONX/c0hQL
VEJWTZNjk5mZn0tubtlIcff9cZGsLwOGkwxFmNCOAkyrn9K2j0WyGuJ9oWKkaGPd
0btqyaxl9cqpyiCZ22YgLc1kSqSGcLLnWVI7RPDY9qV68vDWPDP0FRTcM6frKhGH
/WhnoS9Ubcvb3BOAsE1gWiyrYEBh+QIDAQABo4GnMIGkMB0GA1UdDgQWBBRY7iqf
Lt1pLOaSArQ/S7oRZsTR4jB1BgNVHSMEbjBsgBRY7iqfLt1pLOaSArQ/S7oRZsTR
4qFJpEcwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgTClNvbWUtU3RhdGUxITAfBgNV
BAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZIIJAOQ8OYAdaEDpMAwGA1UdEwQF
MAMBAf8wDQYJKoZIhvcNAQEFBQADggEBACyHZt6FrXFm5i5KN/78Jrh4CRuYPoDA
jgxlIzmeUEFlD7kjSg/jtB1+sWY5e50K1xE5QojUS3L5tciwhr30WRDhVe5OeZ7/
IqOuURkz4JtYgiAQAGvdMyLOnRvTBEok4TZ+vUAwGozbRON1Le86fe0wVud/elQ0
q9OYiugrWcDfDchUSGnAY+tbJSxBNuJTh6LMrut3H7U5TEgV1JP6qFMwX3B19iIE
sYroHpjG8C48JhbisomD/HAQmDTSaij6WNp98vz9mFMx3Run6kjbYNSDcTR8Z1cW
TejZVHhNt7jl+lPIYHD51YcwG7d6nxOYnj4YJRcORghYosSWuHMjDcI=
-----END CERTIFICATE-----
  EOF

  describe '::valid?' do
    it 'returns false if the certificate expires after the provided date' do
      date = DateTime.new(2016, 4, 3)
      result = validator.expired?(certificate, date)
      expect(result).to eq(false)
    end

    it 'returns true if the certificate expires before the provided date' do
      date = DateTime.new(2016, 4, 5)
      result = validator.expired?(certificate, date)
      expect(result).to eq(true)
    end
  end
end
