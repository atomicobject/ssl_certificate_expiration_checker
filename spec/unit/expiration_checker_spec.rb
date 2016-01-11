require 'spec_helper'

describe 'ssl checker' do
  let(:ssl_checker) do
    checker = ::SSLChecker::ExpirationChecker.new
    checker.logger.level = Logger::ERROR
    return checker
  end

  describe '#check_and_notify' do
    it 'returns false if certificate valid and submission succeeded' do
      notifier = instance_double(::SSLChecker::SnitchNotifier).as_null_object
      allow(::SSLChecker::X509::Retriever).to \
        receive(:retrieve).and_return('Cert')
      allow(::SSLChecker::X509::ExpirationChecker).to \
        receive(:expired?).and_return(false)
      allow(notifier).to receive(:notify) { 'asdf' }.and_return(true)

      ssl_checker.send(:notifier=, notifier)

      result = ssl_checker.check_and_notify('asdfexample.com', 443, 'asdf')
      expect(result).to eq(true)
    end

    it 'returns false if certificate valid and submission failed' do
      notifier = instance_double(::SSLChecker::SnitchNotifier).as_null_object
      allow(::SSLChecker::X509::Retriever).to \
        receive(:retrieve).and_return('Cert')
      allow(::SSLChecker::X509::ExpirationChecker).to \
        receive(:expired?).and_return(false)
      allow(notifier).to receive(:notify) { 'asdf' }.and_return(false)

      ssl_checker.send(:notifier=, notifier)

      result = ssl_checker.check_and_notify('asdfexample.com', 443, 'asdf')
      expect(result).to eq(false)
    end

    it 'returns true if certificate invalid and does not submit' do
      allow(::SSLChecker::X509::Retriever).to \
        receive(:retrieve).and_return('Cert')
      allow(::SSLChecker::X509::ExpirationChecker).to \
        receive(:expired?).and_return(true)

      result = ssl_checker.check_and_notify('asdfexample.com', 443, 'asdf')
      expect(result).to eq(false)
    end
  end
end
