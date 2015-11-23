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
    # So this attempts 4 different finds to try and get the resource:
    #
    #   1. If there is a method registered for the provider using
    #      resource_finder_for method, use that and return.
    #   2. If there is no provider, attempt to find by uid alone. This is for
    #      backwards compatibility; we've changed the format of the 'uid' header
    #      in the controller so that it includes a provider. If there is no
    #      provider, we just call against the uid held in the database, as this
    #      is from a login prior to implementing this change.
    #   3. We then search using {provider: provider, uid: uid} to cover the
    #      default behaviour which doesn't allow multiple authentication methods.
    #   4. Finally, we search for cases where a non-email field is being used for
    #      authentication (e.g. username). This is a special case as there will
    #      be a username column on the database, but due to the way the resource
    #      is configured on setup, the "provider" value gets set to "email" (even
    #      though it's actually username)
    #
    # TODO: Refactor the fuck out of this enormous un-DRY method
    #
    def find_resource(id, provider)
      # If a finder method has been registered for this provider, use it!
      finder_method = finder_methods[provider]
      return finder_method.call(id) if finder_method

      # This check is for backwards compatibility. On introducing multiple oauth
      # methods, the uid header changed to include the provider. Prior to this
      # change, however, the uid was only the identifier without the provider.
      # Consequently, if we don't have the provider we fall back to the old
      # behaviour of searching by uid.
      #
      # Original:
      #   find_by(uid: id)
      #
      if provider.nil?
        # TODO: No point downcasing; provider is nil so who cares
        if self.case_insensitive_keys.include?(provider)
          id.downcase!
        end

        query = "uid = ?"

        if ActiveRecord::Base.connection.adapter_name.downcase.starts_with? 'mysql'
          query = "BINARY " + query
        end

        return self.where(query, id).first
      end

      # Original (default behaviour if not allowing multiple auth methods):
      #   find_by(provider: provider, uid: id)
      #
      if self.case_insensitive_keys.include?(provider)
        id.downcase!
      end

      query = "uid = ? AND provider = ?"

      if ActiveRecord::Base.connection.adapter_name.downcase.starts_with? 'mysql'
        query = "BINARY " + query
      end

      resource = self.where(query, id, provider).first
      return resource if resource

      # ZOMGWTF?! Again, the fallback here to provider: 'email' is for
      # backwards compatibility, there may have been setups which used a
      # 'username' as the provider, but the row would have been stored as
      # though their provider were 'email'. This ensures that in those
      # scenarios, we will still successfully find the user
      #
      # Original:
      #   find_by(provider: 'email', uid: id)

      # Safety check to avoid running a query which will explode which doesn't
      # have the provider column
      return nil unless self.columns.map(&:name).include?(provider.to_s)

      if self.case_insensitive_keys.include?(provider)
        id.downcase!
      end

      # TODO: WHat about where the facebook user 12345 doesn't exist? This won't
      # return above, so will cause a query to get run with 'facebook = 12345'
      # which won't be your schema and things will blow up.
      query = "#{provider} = ? AND provider = 'email'"

      if ActiveRecord::Base.connection.adapter_name.downcase.starts_with? 'mysql'
        query = "BINARY " + query
      end

      self.where(query, id).first
    end

    def authentication_field_for(allowed_fields)
      (allowed_fields & authentication_keys).first
    end

    def resource_finder_for(resource, callable)
      finder_methods[resource.to_s] = callable
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

    # TODO: It seems weird that 'create_new_auth_token' returns a full on
    # auth_header. It might be better if this returned just the token, and the
    # caller was responsible for building up an auth header
    return build_auth_header(token, client_id, provider_id, provider)
  end


  def build_auth_header(token, client_id='default', provider_id, provider)
    client_id ||= 'default'

    uid = "#{provider_id} #{provider ? provider : self.try(:provider)}"

    # client may use expiry to prevent validation request if expired
    # must be cast as string or headers will break
    expiry = self.tokens[client_id]['expiry'] || self.tokens[client_id][:expiry]

    return {
      "access-token" => token,
      "token-type"   => "Bearer",
      "client"       => client_id,
      "expiry"       => expiry.to_s,
      "uid"          => uid
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
