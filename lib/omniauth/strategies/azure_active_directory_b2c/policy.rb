module OmniAuth
  module Strategies
    class AzureActiveDirectoryB2C
      class Policy
        include AzureActiveDirectoryB2C::PolicyOptions

        attr_reader :application_identifier, :application_secret, :tenant_name, :policy_name

        def initialize(application_identifier:, application_secret: nil, tenant_name:, policy_name: nil, scope: nil)
          @application_identifier = application_identifier
          @application_secret = application_secret
          @tenant_name = tenant_name
          @policy_name = policy_name
          @scope = *scope
        end

        def authorization_endpoint
          openid_config['authorization_endpoint']
        end

        def token_endpoint
          openid_config['token_endpoint']
        end

        def jwks_uri
          openid_config['jwks_uri']
        end

        def issuer
          openid_config['issuer']
        end

        def scope
          @scope.any? ? @scope : super
        end

        def openid_config
          @openid_config ||= fetch_openid_config
        end

        def jwk_signing_keys
          @jwk_signing_keys ||= fetch_signing_keys
        end

        private

        def fetch_openid_config
          cfg_url = "https://login.microsoftonline.com/#{tenant_name}/.well-known/openid-configuration"
          cfg_url += "?p=#{policy_name}" if policy_name
          config = JSON.parse(Net::HTTP.get(URI(cfg_url)))
          raise StandardError, "error fetching config: #{config['error_description']}" if config['error'].present?
          config
        rescue JSON::ParserError
          raise StandardError, 'Unable to fetch OpenId configuration for AzureAD tenant.'
        end

        def fetch_signing_keys
          raise StandardError, 'No jwks_uri in OpenId config response.' unless jwks_uri
          JSON.parse(Net::HTTP.get(URI(jwks_uri)))
        rescue JSON::ParserError
          raise StandardError, 'Unable to fetch AzureAD signing keys.'
        end
      end # Policy
    end # AzureActiveDirectoryB2C
  end # Strategies
end # OmniAuth
