$LOAD_PATH.unshift(File.expand_path(File.join(File.dirname(__FILE__), 'lib')))

begin
  require 'yaml'
  require 'ssl_checker'
  require 'rspec/core/rake_task'
  require 'rubocop/rake_task'
  RSpec::Core::RakeTask.new(:spec)
  RuboCop::RakeTask.new
rescue LoadError => e
  puts e
end

namespace :ssl do
  desc 'Read hosts to check from config.yml, and run checks.' \
       'Notify configured DMS snitch.'
  task :check_and_notify do
    # Days to look ahead
    lookahead = 14 # days
    failures = 0
    project_root = File.dirname(File.expand_path(__FILE__))
    configuration = YAML.load(File.read(File.join(project_root, 'config.yml')))
    ssl_checker = SSLChecker::ExpirationChecker.new(DateTime.now + lookahead)
    configuration.each do |item|
      failures += 1 unless ssl_checker.check_and_notify(item['host'], \
                                                        item['port'], \
                                                        item['snitch'])
    end
    exit failures
  end

  desc 'Read hosts to check from config.yml, and run checks.'
  task :check do
    # Days to look ahead
    lookahead = 14 # days
    failures = 0
    project_root = File.dirname(File.expand_path(__FILE__))
    configuration = YAML.load(File.read(File.join(project_root, 'config.yml')))
    ssl_checker = SSLChecker::ExpirationChecker.new(DateTime.now + lookahead)
    configuration.each do |item|
      failures += 1 unless ssl_checker.check(item['host'], \
                                             item['port'])
    end
    exit failures
  end
end

desc 'Default'
task default: [:rubocop, :spec]
