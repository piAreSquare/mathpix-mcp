# frozen_string_literal: true

require 'openssl'
require 'securerandom'
require 'rack'

module Mathpix
  module MCP
    # Short-lived, single-use credentials for POST /ocr.
    #
    # The MCP channel is already authenticated — the client holds
    # MATHPIX_MCP_TOKEN — so the server can mint a narrow upload credential and
    # hand it back through a tool call. The caller never needs the long-lived
    # token, which is what makes the upload path work identically from a phone,
    # a laptop, or an unattended scheduled run.
    #
    # Tickets are stateless: the expiry and a nonce are signed with HMAC-SHA256
    # keyed on the bearer token. Nothing is persisted, so a ticket stays valid
    # across a restart and across replicas without a shared store.
    #
    #   <expiry-unix>.<nonce>.<hmac>
    #
    # Expiry is the real guarantee. Single-use is enforced per process via the
    # nonce set below, which is genuinely single-use on one instance and
    # best-effort if the service is scaled to several — a ticket replayed
    # against a different replica inside its TTL would still be accepted. Keep
    # the TTL short; raise it only with that in mind.
    module UploadTicket
      DEFAULT_TTL = 600
      MAX_TTL = 3600

      @used = {}
      @mutex = Mutex.new

      class << self
        # @param secret [String] MATHPIX_MCP_TOKEN
        # @param ttl [Integer] seconds until expiry
        # @return [Hash] ticket string and its expiry
        def mint(secret:, ttl: DEFAULT_TTL)
          raise ArgumentError, 'secret required' if secret.nil? || secret.empty?

          ttl = ttl.to_i.clamp(30, MAX_TTL)
          expires_at = Time.now.to_i + ttl
          payload = "#{expires_at}.#{SecureRandom.hex(12)}"
          { ticket: "#{payload}.#{sign(payload, secret)}", expires_at: expires_at, ttl: ttl }
        end

        # @return [Array(Boolean, String)] validity and a reason when invalid
        def verify(ticket, secret:)
          return [false, 'missing ticket'] if ticket.nil? || ticket.empty?
          return [false, 'server misconfigured'] if secret.nil? || secret.empty?

          expiry, nonce, signature = ticket.to_s.split('.')
          return [false, 'malformed ticket'] if expiry.nil? || nonce.nil? || signature.nil?

          expected = sign("#{expiry}.#{nonce}", secret)
          return [false, 'bad signature'] unless Rack::Utils.secure_compare(expected, signature)
          return [false, 'ticket expired'] if Time.now.to_i > expiry.to_i
          return [false, 'ticket already used'] unless claim(nonce, expiry.to_i)

          [true, 'ok']
        end

        private

        def sign(payload, secret)
          OpenSSL::HMAC.hexdigest('SHA256', secret, payload)
        end

        # Record the nonce, refusing a second use. Entries are dropped once the
        # ticket could no longer be valid anyway, so this cannot grow without
        # bound.
        def claim(nonce, expiry)
          now = Time.now.to_i
          @mutex.synchronize do
            @used.delete_if { |_, exp| exp < now }
            return false if @used.key?(nonce)

            @used[nonce] = expiry
            true
          end
        end
      end
    end
  end
end
