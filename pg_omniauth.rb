pg_port = ask("What port are you going to use for this postgresql instance?")
pg_port = "5432" if pg_port.blank?

create_file '.env' do <<-EOF
PG_PORT: #{pg_port}
EOF
end

inject_into_file 'config/secrets.yml', "  db_port: <%= ENV['PG_PORT'] %>\n", after: "development:\n"

inject_into_file 'config/secrets.yml', "  db_port: <%= ENV['PG_PORT'] %>\n", after: "test:\n"

inject_into_file 'config/database.yml',
  :before => "default:" do <<-YAML
local: &local
  pg_port: Rails.application.secrets.db_port

YAML
end

inject_into_file 'config/database.yml',
  :after => "development:" do <<-YAML

  <<: *local
YAML
end

inject_into_file 'config/database.yml',
  :after => "test:" do <<-YAML

  <<: *local
YAML
end

# see http://mauricio.github.io/2014/02/09/foreman-and-environment-variables.html
create_file 'Procfile.dev' do <<-EOF
postgresql: postgres -p #{pg_port} -D vendor/postgresql
rails: bundle exec rails s -b 0.0.0.0 -p $PORT
guard: bundle exec guard --no-interactions
EOF
end

app_port = ask("On which port do you want to run this application?")
app_port = "5000" if app_port.blank?

create_file '.foreman' do <<-EOF
port: #{app_port}
EOF
end

run "echo #{app_port.to_i+100} > ~/.pow/#{app_name}"

gem 'activerecord-colored_log_subscriber' # colorized SQL logging, will be the default on Rails 5
gem 'devise'
gem 'rack-mini-profiler'

# Use Puma as the app server
gem 'puma'

gem_group :development, :test do
  gem 'rspec-rails', '~> 3.0'
  gem 'factory_girl_rails'
end

gem_group :test do
  gem 'database_cleaner'
  gem 'capybara'
  gem 'shoulda-matchers'
  gem 'simplecov', :require => false
end

gem_group :development do
  # Preview mail in the browser instead of sending it.
  gem 'letter_opener_web', '~> 1.2.0'

  gem 'annotate', '~> 2.6.6'
  gem 'bullet'
  gem 'guard-rspec', require: false
  gem 'quiet_assets'
end

run 'bundle install --path .bundle'

run "pg_ctl init -D vendor/postgresql"

initializer 'mini_profiler.rb', <<-CODE
Rack::MiniProfiler.config.position = 'right'
Rack::MiniProfiler.config.start_hidden = true
CODE

#rake 'db:create'

inject_into_file 'config/application.rb',
  after: "config.active_record.raise_in_transactional_callbacks = true\n" do <<-RUBY
    config.generators do |g|
      g.stylesheets     false
      g.javascripts     false
    end
RUBY
end

generate 'rspec:install'
run 'bundle binstubs rspec-core'

create_file '.simplecov' do <<-EOF
SimpleCov.start 'rails' do
  add_filter '/.bundle/'
  add_group "Uploaders", "app/uploaders"
end
EOF
end

inject_into_file 'spec/rails_helper.rb', "require 'simplecov'\n", after: "ENV['RAILS_ENV'] ||= 'test'\n"
inject_into_file 'spec/rails_helper.rb', "require 'capybara/rspec'\n", after: "# Add additional requires below this line. Rails is not loaded until this point!\n"
inject_into_file 'spec/rails_helper.rb', "require 'capybara/rails'\n", after: "# Add additional requires below this line. Rails is not loaded until this point!\n"
inject_into_file 'spec/rails_helper.rb',
  :before => /^end/ do <<-RUBY

  config.include Devise::TestHelpers, type: :controller
  config.include Rails.application.routes.url_helpers

  # Include Factory Girl syntax to simplify calls to factories
  config.include FactoryGirl::Syntax::Methods

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
RUBY
end

route <<-EOF
if Rails.env.development?
    mount LetterOpenerWeb::Engine, at: '/letter_opener'
  end
EOF

generate 'annotate:install'
generate 'devise:install'

initializer 'bullet.rb', <<-CODE
if defined? Bullet
  Bullet.enable = true # this is to actually enable the gem
  Bullet.bullet_logger = true
  Bullet.console = true
  Bullet.add_footer = true
end
CODE

run 'bundle exec guard init rspec'

git :init
git add: "."
git commit: "-m 'Project initialization'"

if yes?('Do you want to create a devise model now? (yes/no)')
  devise_model = ask("What would you want to name it? (empty for the default 'User')")
  devise_model = "User" if devise_model.blank?
  generate "devise #{devise_model}"
end

if yes?('Do you want to add omniauth authentication? (yes/no)')

  generate 'model identity user:references provider:string uid:string'

  inject_into_file 'app/models/identity.rb',
    before: /^end/ do <<-RUBY
  belongs_to #{devise_model.downcase.to_sym}

  validates_presence_of :uid, :provider
  validates_uniqueness_of :uid, :scope => :provider

  def self.find_for_oauth(auth)
    find_or_create_by(uid: auth.uid, provider: auth.provider)
  end
RUBY
end

  gsub_file 'config/routes.rb', /devise_for :users/, "devise_for :users, :controllers => { omniauth_callbacks: 'omniauth_callbacks' }"

  create_file 'app/controllers/omniauth_callbacks_controller' do <<-'RUBY'
class OmniauthCallbacksController < Devise::OmniauthCallbacksController
  skip_before_action :authenticate_user!

  def self.provides_callback_for(provider)
    class_eval %Q{
      def #{provider}
        @user = User.find_for_oauth(env["omniauth.auth"], current_user)

        if @user.persisted?
          sign_in_and_redirect @user, event: :authentication
          set_flash_message(:notice, :success, kind: "#{provider}".capitalize) if is_navigational_format?
        else
          session["devise.#{provider}_data"] = env["omniauth.auth"]
          redirect_to new_user_registration_url
        end
      end
    }
  end

  [:facebook].each do |provider|
    provides_callback_for provider
  end

  def after_sign_in_path_for(resource)
    if resource.email_verified?
      super resource
    else
      finish_signup_path(resource)
    end
  end
end
RUBY
  end

  inject_into_file 'app/models/user.rb',
    before: /^end/ do <<-'RUBY'
  TEMP_EMAIL_PREFIX = 'change@me'
  TEMP_EMAIL_REGEX = /\Achange@me/

  validates_format_of :email, :without => TEMP_EMAIL_REGEX, on: :update

  def self.find_for_oauth(auth, signed_in_resource = nil)
    # Get the identity and user if they exist
    identity = Identity.find_for_oauth(auth)

    # If a signed_in_resource is provided it always overrides the existing user
    # to prevent the identity being locked with accidentally created accounts.
    # Note that this may leave zombie accounts (with no associated identity) which
    # can be cleaned up at a later date.
    user = signed_in_resource ? signed_in_resource : identity.user

    # Create the user if needed
    if user.nil?

      # Get the existing user by email if the provider gives us a verified email.
      # If no verified email was provided we assign a temporary email and ask the
      # user to verify it on the next step via UsersController.finish_signup
      email_is_verified = auth.info.email && (auth.info.verified || auth.info.verified_email)
      email = auth.info.email if email_is_verified
      user = User.where(:email => email).first if email

      # Create the user if it's a new registration
      if user.nil?
        user = User.new(
          first_name: auth.extra.raw_info.first_name,
          last_name: auth.extra.raw_info.last_name,
          #username: auth.info.nickname || auth.uid,
          email: email ? email : "#{TEMP_EMAIL_PREFIX}-#{auth.uid}-#{auth.provider}.com",
          password: Devise.friendly_token[0,20]
        )
        user.skip_confirmation!
        user.save!
      end
    end

    # Associate the identity with the user if needed
    if identity.user != user
      identity.user = user
      identity.save!
    end
    user
  end

  def email_verified?
    self.email && self.email !~ TEMP_EMAIL_REGEX
  end
RUBY
  end

  route "match '/users/:id/finish_signup' => 'users#finish_signup', via: [:get, :patch], :as => :finish_signup"

  inject_into_file 'config/secrets.yml', "  omniauth:\n", after: "development:\n"

  gsub_file 'app/models/user.rb', /:validatable/, ':validatable, :omniauthable'

  if yes?('Do you want to allow signing in via Facebook?')
    gem 'omniauth-facebook'
    run 'bundle install'

    inject_into_file 'config/secrets.yml',
        after: "omniauth:\n" do <<-YAML
    facebook:
      app_id: <%= ENV["FACEBOOK_APP_ID"] %>
      app_secret: <%= ENV["FACEBOOK_APP_SECRET"] %>
YAML
    end

    inject_into_file 'config/initializers/devise.rb',
      after: "# config.omniauth :github, 'APP_ID', 'APP_SECRET', scope: 'user,public_repo'\n" do <<-RUBY
  config.omniauth :facebook,
                  Rails.application.secrets.omniauth['facebook']['app_id'],
                  Rails.application.secrets.omniauth['facebook']['app_secret'],
                  info_fields: 'name,email,first_name,last_name,middle_name,verified'
RUBY
    end

    git add: "."
    git commit: "-m 'Setup omniauth'"

  end
end

