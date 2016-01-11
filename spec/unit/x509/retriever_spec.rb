require 'spec_helper'

describe 'x509 retriever' do
  let(:retriever) { ::SSLChecker::X509::Retriever }

  describe '#retrieve' do
    it 'opens a tcp connection and ssl session and retrieves the certificate' do
      tcp_server = double(TCPSocket).as_null_object
      ssl_server = double(OpenSSL::SSL::SSLSocket).as_null_object
      allow(TCPSocket).to receive(:new).and_return(tcp_server)
      allow(OpenSSL::SSL::SSLSocket).to receive(:new).and_return(ssl_server)
      allow(tcp_server).to receive(:close).and_return(true)
      allow(ssl_server).to \
        receive(:peer_cert).and_return('Base64 Encoded Certificate')

      expect(ssl_server).to receive(:connect)
      expect(ssl_server).to receive(:peer_cert)
      expect(ssl_server).to receive(:sysclose)
      expect(tcp_server).to receive(:close)

      cert = retriever.retrieve('example.com', 443)
      expect(cert).to eq('Base64 Encoded Certificate')
    end

    it 'throws a socket error due to non-existant address' do
      allow(TCPSocket).to receive(:new).and_return(SocketError)

      expect { retriever.retrieve('example.com', 443) }.to raise_error
    end
  end
end
