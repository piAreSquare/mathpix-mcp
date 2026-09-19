# frozen_string_literal: true

require 'time'
require_relative '../base_tool'
require_relative '../upload_ticket'

module Mathpix
  module MCP
    module Tools
      # Issues a short-lived upload credential for POST /ocr.
      #
      # The MCP tools can only read a path on this container or a public URL, so
      # a document on the caller's own machine has no way in. This tool closes
      # that gap over the channel that is already authenticated: it returns a
      # signed, single-use URL the caller can POST the file to, without ever
      # handling the long-lived bearer token.
      class CreateUploadTicketTool < BaseTool
        description 'Get a short-lived, single-use URL for uploading a local document to this ' \
                    'server for OCR. POST the file to upload_url as multipart field "file"; the ' \
                    'response carries a pdf_id to poll. Use this when the document is on the ' \
                    "caller's machine rather than at a public URL."

        input_schema(
          properties: {
            ttl: {
              type: 'number',
              description: 'Seconds the ticket stays valid (default 600, max 3600).'
            }
          },
          required: []
        )

        def self.call(server_context:, ttl: UploadTicket::DEFAULT_TTL)
          secret = ENV.fetch('MATHPIX_MCP_TOKEN', nil)
          if secret.nil? || secret.empty?
            return json_response(
              error: true,
              message: 'MATHPIX_MCP_TOKEN is not set, so upload tickets cannot be signed.'
            )
          end

          base = public_base_url
          unless base
            return json_response(
              error: true,
              message: 'Cannot determine this service\'s public URL. Set MATHPIX_PUBLIC_URL ' \
                       '(e.g. https://your-app.up.railway.app).'
            )
          end

          issued = UploadTicket.mint(secret: secret, ttl: ttl)
          json_response(
            success: true,
            upload_url: "#{base}/ocr",
            ticket: issued[:ticket],
            expires_at: Time.at(issued[:expires_at]).utc.iso8601,
            ttl_seconds: issued[:ttl],
            usage: 'POST multipart/form-data to upload_url with field "file", and send the ' \
                   'ticket as the X-Upload-Ticket header (or ?ticket=). Optional fields: ' \
                   'formats, page_ranges, wait. Returns 202 with a pdf_id.'
          )
        end

        # Railway, Render and Fly all expose the external hostname in the
        # environment; MATHPIX_PUBLIC_URL overrides for anything else.
        def self.public_base_url
          explicit = ENV.fetch('MATHPIX_PUBLIC_URL', nil)
          return explicit.chomp('/') unless explicit.nil? || explicit.empty?

          domain = ENV['RAILWAY_PUBLIC_DOMAIN'] || ENV['RENDER_EXTERNAL_HOSTNAME'] || ENV['FLY_APP_NAME']
          return nil if domain.nil? || domain.empty?

          domain = "#{domain}.fly.dev" if domain == ENV['FLY_APP_NAME'] && !domain.include?('.')
          "https://#{domain}"
        end
      end
    end
  end
end
