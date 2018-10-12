module OmniAuth
  module Strategies
    class AzureActiveDirectoryB2C
      class AuthenticationResponse

        class AuthenticationMethod
          BASIC = 'basic'
          BODY = 'body'
          POST = 'post'
        end

        attr_reader :policy, :client, :code

        def initialize(policy, code, encrypted_id_token)
          @policy = policy
          @code = code
          @encrypted_id_token = encrypted_id_token
        end

        def id_token
          @id_token ||= get_id_token!
        end

        def subject_id
          id_token.sub
        end

        def user_info
          {
            name: id_token.raw_attributes['name'],
            email: id_token.raw_attributes['email'] || id_token.raw_attributes['emails']&.first,
            nickname: id_token.raw_attributes['preferred_username'],
            first_name: id_token.raw_attributes['given_name'],
            last_name: id_token.raw_attributes['family_name'],
            gender: id_token.raw_attributes['gender'],
            image: id_token.raw_attributes['picture'],
            phone: id_token.raw_attributes['phone_number'],
            urls: { website: id_token.raw_attributes['website'] }
          }
        end

        def extra_info
          { raw_info: id_token.raw_attributes }
        end

        def scope
          policy.scope
        end

        def authentication_method
          AuthenticationMethod::BODY
        end

        def credentials
          {
            code: code,
            scope: scope
          }
        end

        def get_id_token!
          decoded_id_token = decode_id_token!(@encrypted_id_token)
        end

        def decode_id_token!(id_token)
          ::OpenIDConnect::ResponseObject::IdToken.decode(id_token, public_key)
        end

        def public_key
          if policy.jwk_signing_algorithm == :RS256 && policy.jwk_signing_keys
            jwk_key
          else
            raise 'id_token signing algorithm is currently not supported: %s' % policy.jwk_signing_algorithm
          end
        end

        def jwk_key
          key = policy.jwk_signing_keys
          if key.has_key?('keys')
            JSON::JWK::Set.new(key['keys']) # a set of keys
          else
            JSON::JWK.new(key) # a single key
          end
        end

        def validate_id_token(seconds_since_epoc = Time.now.to_i)
          JwtValidator.validate(id_token.raw_attributes, public_key, policy, seconds_since_epoc)
        end

      end # AuthenticationResponse
    end # AzureActiveDirectoryB2C
  end # Strategies
end # OmniAuth
