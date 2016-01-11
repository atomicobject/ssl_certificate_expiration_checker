require 'spec_helper'

describe 'snitch notifier' do
  let(:notifier) do
    notifier = ::SSLChecker::SnitchNotifier.new
    notifier.logger.level = Logger::ERROR
    return notifier
  end

  describe '::new' do
    it 'has a logger' do
      expect(notifier.logger).to be_a(Logger)
    end

    it 'sets up an HTTP connection to deadmansnitch' do
      expect(notifier.http).to be_a(Net::HTTP)
      expect(notifier.http.address).to eq('nosnch.in')
      expect(notifier.http.port).to eq(443)
      expect(notifier.http.use_ssl?).to eq(true)
    end
  end

  describe '#notify' do
    it 'performs a HTTP get to deadmansnitch with a given ID' do
      http = instance_double(Net::HTTP)

      notifier.send(:http=, http)

      expect(http).to receive(:get).with('/asdfasdf')
      notifier.notify('asdfasdf')
    end

    it 'returns true if the HTTP get was a success' do
      http = instance_double(Net::HTTP)
      http_response = instance_double(Net::HTTPSuccess, body: 'Looks good')
      allow(http).to receive(:get).and_return(http_response)
      allow(http_response).to \
        receive(:is_a?) { Net::HTTPSuccess }.and_return(true)

      notifier.send(:http=, http)

      result = notifier.notify('asdfasdf')
      expect(result).to eq(true)
    end

    it 'returns false if the HTTP get was not a success' do
      http = instance_double(Net::HTTP)
      http_response = instance_double(Net::HTTPError)
      allow(http).to receive(:get).and_return(http_response)

      notifier.send(:http=, http)

      result = notifier.notify('asdfasdf')
      expect(result).to eq(false)
    end
  end
end
