module OmniAuth
  module Strategies
    class AzureActiveDirectoryB2C
      class AuthenticationRequest

        class ResponseType
          # TODO: provide constants for each option
          ID_TOKEN = 'id_token'
          CODE = 'code'
        end

        attr_reader :policy, :client

        def initialize(policy, redirect_uri:, **override_options)
          @policy = policy
          @client = policy.initialize_client({ redirect_uri: redirect_uri, **override_options })
        end

        def authorization_uri(**override_options)
          options = default_authorization_uri_options.merge(override_options)
          options = options.select {|k, v| v }
          client.authorization_uri(options)
        end

        def state
          @state ||= SecureRandom.hex(16)
        end

        def nonce
          @nonce ||= SecureRandom.hex(16)
        end

        def response_type
          [ResponseType::CODE, ResponseType::ID_TOKEN].join(' ')
        end

        def default_authorization_uri_options
          {
            response_type: response_type,
            response_mode: 'form_post',
            scope: policy.scope,
            state: state,
            nonce: nonce,
          }
        end

      end # AuthenticationRequest
    end # AzureActiveDirectoryB2C
  end # Strategies
end # OmniAuth
