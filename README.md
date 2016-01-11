# SSL Certificate Expiration Checker

## Getting Started

  - Add a config file at config/config.yml following the pattern in config/config.yml.example.
  - Run `bundle install`
  - Run `bundle exec rake ssl:check` to just run checks.
  - Run `bundle exec rake ssl:check_and_notify` to run checks, and send notifications to the configured DMS snitch.
