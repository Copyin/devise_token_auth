require 'bcrypt'

module DeviseTokenAuth::Concerns::User
  extend ActiveSupport::Concern

  def self.tokens_match?(token_hash, token)
    @token_equality_cache ||= {}

    key = "#{token_hash}/#{token}"
    result = @token_equality_cache[key] ||= (::BCrypt::Password.new(token_hash) == token)
    if @token_equality_cache.size > 10000
      @token_equality_cache = {}
    end
    result
  end


  included do
    # Hack to check if devise is already enabled
    unless self.method_defined?(:devise_modules)
      devise :database_authenticatable, :registerable,
          :recoverable, :trackable, :validatable, :confirmable
    else
      self.devise_modules.delete(:omniauthable)
    end

    unless tokens_has_json_column_type?
      serialize :tokens, JSON
    end

    validates :email, presence: true, email: true, if: Proc.new { |u| u.provider == 'email' }
    validates_presence_of :uid, if: Proc.new { |u| u.provider != 'email' }

    # only validate unique emails among email registration users
    validate :unique_email_user, on: :create

    # can't set default on text fields in mysql, simulate here instead.
    after_save :set_empty_token_hash
    after_initialize :set_empty_token_hash

    # keep uid in sync with email
    before_save :sync_uid
    before_create :sync_uid

    # get rid of dead tokens
    before_save :destroy_expired_tokens

    # allows user to change password without current_password
    attr_writer :allow_password_change
    def allow_password_change
      @allow_password_change || false
    end

    # don't use default devise email validation
    def email_required?
      false
    end

    def email_changed?
      false
    end

    # override devise method to include additional info as opts hash
    def send_confirmation_instructions(opts=nil)
      unless @raw_confirmation_token
        generate_confirmation_token!
      end

      opts ||= {}

      # fall back to "default" config name
      opts[:client_config] ||= "default"

      if pending_reconfirmation?
        opts[:to] = unconfirmed_email
      end

      send_devise_notification(:confirmation_instructions, @raw_confirmation_token, opts)
    end

    # override devise method to include additional info as opts hash
    def send_reset_password_instructions(opts=nil)
      token = set_reset_password_token

      opts ||= {}

      # fall back to "default" config name
      opts[:client_config] ||= "default"

      send_devise_notification(:reset_password_instructions, token, opts)

      token
    end
  end

  module ClassMethods

    # This attempts 4 different finds to try and get the resource, depending on
    # how the resources have been configured and accounting for backwards
    # compatibility prior to multiple authentication methods.
    #
    def find_resource(id, provider)
      # 1. If a finder method has been registered for this provider, use it!
      #
      finder_method = finder_methods[provider.try(:to_sym)]
      return finder_method.call(id) if finder_method

      # 2. This check is for backwards compatibility. On introducing multiple
      #    oauth methods, the uid header changed to include the provider. Prior
      #    to this change, however, the uid was only the identifier.
      #    Consequently, if we don't have the provider we fall back to the old
      #    behaviour of searching by uid.
      #
      return case_sensitive_find("uid = ?", id) if provider.nil?

      id.downcase! if self.case_insensitive_keys.include?(provider.to_sym)

      # 3. We then search using {provider: provider, uid: uid} to cover the
      #    default behaviour which doesn't allow multiple authentication
      #    methods for a single resource
      #
      resource = case_sensitive_find("uid = ? AND provider = ?", id, provider)
      return resource if resource

      # 4. If we're at this point, we've either:
      #
      #  A. Got someone who hasn't registered yet
      #  B. Are using a non-email field to identify users
      #
      # If A is the case, we likely won't have a column which corresponds to
      # the value of "provider" (e.g. "twitter"). Consequently, bail out to
      # avoid running a query selecting on a column we don't have.
      #
      return nil unless self.columns.map(&:name).include?(provider.to_s)

      # The use of provider: 'email' is for backwards compatibility. There may
      # have been setups which used a 'username' as the provider, but the row
      # would have been stored as though their provider were 'email'. This
      # ensures that in those scenarios, we will still successfully find the
      # resource
      case_sensitive_find("#{provider} = ? AND provider = 'email'", id)
    end

    def case_sensitive_find(query, *args)
      if ActiveRecord::Base.connection.adapter_name.downcase.starts_with? 'mysql'
        query = "BINARY " + query
      end

      where(query, *args).first
    end

    def authentication_field_for(allowed_fields)
      (allowed_fields & authentication_keys).first
    end

    def resource_finder_for(resource, callable)
      finder_methods[resource.to_sym] = callable
    end

    def finder_methods
      @@finder_methods ||= {}
    end

    protected


    def tokens_has_json_column_type?
      table_exists? && self.columns_hash['tokens'] && self.columns_hash['tokens'].type.in?([:json, :jsonb])
    end
  end


  def valid_token?(token, client_id='default')
    client_id ||= 'default'

    return false unless self.tokens[client_id]

    return true if token_is_current?(token, client_id)
    return true if token_can_be_reused?(token, client_id)

    # return false if none of the above conditions are met
    return false
  end


  # this must be done from the controller so that additional params
  # can be passed on from the client
  def send_confirmation_notification?
    false
  end


  def token_is_current?(token, client_id)
    # ghetto HashWithIndifferentAccess
    expiry     = self.tokens[client_id]['expiry'] || self.tokens[client_id][:expiry]
    token_hash = self.tokens[client_id]['token'] || self.tokens[client_id][:token]

    return true if (
      # ensure that expiry and token are set
      expiry and token and

      # ensure that the token has not yet expired
      DateTime.strptime(expiry.to_s, '%s') > Time.now and

      # ensure that the token is valid
      DeviseTokenAuth::Concerns::User.tokens_match?(token_hash, token)
    )
  end


  # allow batch requests to use the previous token
  def token_can_be_reused?(token, client_id)
    # ghetto HashWithIndifferentAccess
    updated_at = self.tokens[client_id]['updated_at'] || self.tokens[client_id][:updated_at]
    last_token = self.tokens[client_id]['last_token'] || self.tokens[client_id][:last_token]


    return true if (
      # ensure that the last token and its creation time exist
      updated_at and last_token and

      # ensure that previous token falls within the batch buffer throttle time of the last request
      Time.parse(updated_at) > Time.now - DeviseTokenAuth.batch_request_buffer_throttle and

      # ensure that the token is valid
      ::BCrypt::Password.new(last_token) == token
    )
  end


  # update user's auth token (should happen on each request)
  def create_new_auth_token(client_id=nil, provider_id=nil, provider=nil)
    client_id  ||= SecureRandom.urlsafe_base64(nil, false)
    last_token ||= nil
    token        = SecureRandom.urlsafe_base64(nil, false)
    token_hash   = ::BCrypt::Password.create(token)
    expiry       = (Time.now + DeviseTokenAuth.token_lifespan).to_i

    if self.tokens[client_id] and self.tokens[client_id]['token']
      last_token = self.tokens[client_id]['token']
    end

    self.tokens[client_id] = {
      token:      token_hash,
      expiry:     expiry,
      last_token: last_token,
      updated_at: Time.now
    }

    max_clients = DeviseTokenAuth.max_number_of_devices
    while self.tokens.keys.length > 0 and max_clients < self.tokens.keys.length
      oldest_token = self.tokens.min_by { |cid, v| v[:expiry] || v["expiry"] }
      self.tokens.delete(oldest_token.first)
    end

    self.save!

    # REVIEW: It seems weird that 'create_new_auth_token' returns a full on
    # auth_header rather than just the token it's created. It might be better
    # if this returned just the token, and the caller was responsible for
    # building up an auth header. The main reason it returns the auth header
    # here is to simplify testing, which is not a great reason to do it.
    return build_auth_header(token, client_id, provider_id, provider)
  end

  # TODO: Document provider_id/provider a bit better
  def build_auth_header(token, client_id='default', provider_id, provider)
    client_id ||= 'default'

    # If we've not been given a specific provider, intuit it. This may occur
    # when logging in through standard devise (for example). See the check
    # for DeviseTokenAuth.enable_standard_devise_support in:
    #
    #  DeviseAuthToken::SetUserToken#set_user_token
    #
    provider    = self.class.authentication_keys.first if provider.nil?
    provider_id = self.send(provider)                  if provider_id.nil?

    # client may use expiry to prevent validation request if expired
    # must be cast as string or headers will break
    expiry = self.tokens[client_id]['expiry'] || self.tokens[client_id][:expiry]

    return {
      "access-token" => token,
      "token-type"   => "Bearer",
      "client"       => client_id,
      "expiry"       => expiry.to_s,
      "uid"          => "#{provider_id} #{provider}"
    }
  end

  def build_auth_url(base_url, args)
    args[:uid]    = self.uid
    args[:expiry] = self.tokens[args[:client_id]]['expiry']

    DeviseTokenAuth::Url.generate(base_url, args)
  end


  def extend_batch_buffer(token, client_id, provider_id, provider)
    self.tokens[client_id]['updated_at'] = Time.now
    self.save!

    return build_auth_header(token, client_id, provider_id, provider)
  end

  def confirmed?
    self.devise_modules.exclude?(:confirmable) || super
  end

  def token_validation_response
    self.as_json(except: [
      :tokens, :created_at, :updated_at
    ])
  end


  protected

  # only validate unique email among users that registered by email
  def unique_email_user
    if provider == 'email' and self.class.where(provider: 'email', email: email).count > 0
      errors.add(:email, :already_in_use)
    end
  end

  def set_empty_token_hash
    self.tokens ||= {} if has_attribute?(:tokens)
  end

  def sync_uid
    self.uid = email if provider == 'email'
  end

  def destroy_expired_tokens
    if self.tokens
      self.tokens.delete_if do |cid, v|
        expiry = v[:expiry] || v["expiry"]
        DateTime.strptime(expiry.to_s, '%s') < Time.now
      end
    end
  end

end
