# frozen_string_literal: true

require 'json'
require 'rack'
require 'mathpix/mcp/upload_ticket'

module Mathpix
  module MCP
    # Bearer-guarded HTTP surface for submitting a document straight to Mathpix.
    #
    # The MCP tools can only read a path on THIS container or a public URL, so a
    # file sitting on a phone or a laptop has no way in. This route closes that
    # gap without ever putting the document on a public URL: the client POSTs the
    # bytes, this process forwards them to Mathpix using the credentials it
    # already holds, and the file is deleted as soon as the upload completes.
    #
    # Submission is asynchronous by design. Mathpix returns a conversion id in
    # seconds and does the work on its own servers, so holding the HTTP request
    # open until a long document finishes would only risk the edge proxy timing
    # the request out. Nothing is retained here between calls — no volume, no
    # staged file, and no dependence on which container instance serves the
    # follow-up request.
    #
    #   POST /ocr          multipart: file=@doc.pdf [, formats, page_ranges, wait]
    #   GET  /ocr/<id>     conversion status
    #   GET  /ocr/<id>/result   converted content
    #
    # Mount behind Mathpix::MCP::HttpApp::BearerAuth — it holds no auth of its own.
    module OcrApp
      module_function

      DEFAULT_FORMATS = [:markdown].freeze
      # Names callers naturally reach for, mapped to the result keys.
      ALIASES = { md: :markdown, mmd: :markdown, tex: :latex }.freeze
      # Mathpix accepts up to 1 GB per document on multipart upload.
      DEFAULT_MAX_MB = 1024
      # Cap for the optional blocking mode, kept well under typical edge timeouts.
      MAX_BLOCKING_WAIT = 240

      def build(max_size_mb: Integer(ENV.fetch('MATHPIX_MAX_UPLOAD_MB', DEFAULT_MAX_MB.to_s)))
        ->(env) { call(env, max_size_mb) }
      end

      # Accepts either the long-lived bearer token or a signed upload ticket
      # minted through the MCP channel by create_upload_ticket_tool.
      #
      # The ticket is read only from the X-Upload-Ticket header or the query
      # string — never from the request body. Touching the body here would mean
      # buffering an entire document to disk before discovering the credential
      # is invalid.
      def guarded(token:, **options)
        app = build(**options)

        lambda do |env|
          presented = env['HTTP_AUTHORIZATION'].to_s.sub(/\ABearer\s+/i, '')
          if !token.to_s.empty? && Rack::Utils.secure_compare(token.to_s, presented)
            return app.call(env)
          end

          ticket = env['HTTP_X_UPLOAD_TICKET'].to_s
          if ticket.empty?
            ticket = Rack::Utils.parse_nested_query(env['QUERY_STRING'].to_s)['ticket'].to_s
          end

          ok, reason = UploadTicket.verify(ticket, secret: token)
          return app.call(env) if ok

          json(401, error: 'Unauthorized', reason: reason)
        end
      end

      def call(env, max_size_mb)
        request = Rack::Request.new(env)
        segments = request.path_info.split('/').reject(&:empty?)

        if request.post? && segments.empty?
          submit(request, max_size_mb)
        elsif request.get? && segments.length == 1
          status(segments[0])
        elsif request.get? && segments.length == 2 && segments[1] == 'result'
          result(segments[0], request)
        else
          json(404, error: 'POST /ocr, GET /ocr/<id>, GET /ocr/<id>/result')
        end
      rescue Mathpix::Error => e
        json(502, error: e.message, type: e.class.name)
      rescue StandardError => e
        json(500, error: e.class.name)
      end

      # --- POST /ocr -------------------------------------------------------

      def submit(request, max_size_mb)
        max_bytes = max_size_mb * 1024 * 1024

        # Reject on the declared length before Rack buffers the body to disk,
        # so an oversized upload costs neither time nor container disk.
        declared = request.content_length.to_i
        if declared > max_bytes
          return json(413, error: "file exceeds #{max_size_mb} MB", bytes: declared)
        end

        upload = request.params['file']
        unless upload.is_a?(Hash) && upload[:tempfile]
          return json(400, error: 'multipart field "file" is required')
        end

        path = upload[:tempfile].path
        size = File.size(path)
        return json(413, error: "file exceeds #{max_size_mb} MB", bytes: size) if size > max_bytes

        document = Mathpix::Document.new(Mathpix.client, path)
        document.with_formats(*formats_from(request))
        if (ranges = request.params['page_ranges']) && !ranges.to_s.empty?
          document.options[:page_ranges] = ranges
        end

        # Returns as soon as Mathpix has accepted the bytes; the file is not
        # needed after this point because Mathpix now holds it.
        conversion = document.convert
        discard(upload)

        if truthy?(request.params['wait'])
          wait = [request.params.fetch('max_wait', 120).to_i, MAX_BLOCKING_WAIT].min
          conversion.wait_until_complete(max_wait: wait, poll_interval: 3.0)
          return json(200, payload_for(conversion.conversion_id, conversion.result))
        end

        json(202,
             pdf_id: conversion.conversion_id,
             bytes: size,
             filename: upload[:filename],
             status_url: "/ocr/#{conversion.conversion_id}",
             result_url: "/ocr/#{conversion.conversion_id}/result")
      rescue Mathpix::TimeoutError => e
        # The conversion is still running at Mathpix; hand back the id so the
        # caller can poll rather than losing the work.
        json(202, pdf_id: conversion&.conversion_id, note: e.message)
      ensure
        discard(upload)
      end

      # --- GET /ocr/<id> ---------------------------------------------------

      def status(conversion_id)
        data = Mathpix.client.get_document_status(conversion_id)
        json(200,
             pdf_id: conversion_id,
             status: data['status'],
             pages: data['num_pages'],
             percent_done: data['percent_done'])
      end

      # --- GET /ocr/<id>/result --------------------------------------------

      def result(conversion_id, request)
        conversion = Mathpix::DocumentConversion.new(
          Mathpix.client, conversion_id, "#{conversion_id}.pdf", :pdf
        )
        # Already-completed conversions return on the first poll; this only
        # blocks if the caller polled early.
        wait = [request.params.fetch('max_wait', 30).to_i, MAX_BLOCKING_WAIT].min
        conversion.wait_until_complete(max_wait: wait, poll_interval: 3.0)
        json(200, payload_for(conversion_id, conversion.result, formats_from(request)))
      rescue Mathpix::TimeoutError
        json(202, pdf_id: conversion_id, status: 'processing')
      end

      # --- helpers ---------------------------------------------------------

      # Mathpix populates every format it produced, not only the ones asked
      # for — its HTML rendering alone is ~34 KB of boilerplate per document.
      # Returning it unasked is pure waste for a caller that wanted Markdown,
      # so the response carries only the requested formats.
      def payload_for(conversion_id, result, formats = DEFAULT_FORMATS)
        available = {
          markdown: result.markdown,
          latex: result.latex,
          html: result.html
        }.compact

        wanted = formats.map { |f| ALIASES.fetch(f, f) }
        contents = available.select { |format, _| wanted.include?(format) }
        # Never return an empty body because of an unrecognised format name.
        contents = available.slice(:markdown) if contents.empty?
        contents = available if contents.empty?

        {
          success: true,
          pdf_id: conversion_id,
          pages: positive_or_nil(result.page_count),
          processing_time: result.processing_time,
          chars: contents.transform_values(&:length),
          omitted: (available.keys - contents.keys),
          results: contents
        }
      end

      # page_count comes back as 0 on some payloads even when the conversion
      # reported pages; report nothing rather than a misleading zero.
      def positive_or_nil(value)
        value.to_i.positive? ? value.to_i : nil
      end

      def formats_from(request)
        raw = request.params['formats'].to_s
        return DEFAULT_FORMATS if raw.empty?

        parsed = raw.split(',').map { |f| f.strip.downcase }.reject(&:empty?).map(&:to_sym)
        parsed.empty? ? DEFAULT_FORMATS : parsed
      end

      def truthy?(value)
        %w[1 true yes on].include?(value.to_s.strip.downcase)
      end

      # Remove the buffered upload as early as possible; this container keeps
      # no copy of anyone's document.
      def discard(upload)
        return unless upload.is_a?(Hash)

        tempfile = upload[:tempfile]
        return unless tempfile

        tempfile.close unless tempfile.closed?
        tempfile.unlink
      rescue StandardError
        nil
      end

      def json(status, payload)
        [status, { 'content-type' => 'application/json' }, [JSON.generate(payload)]]
      end
    end
  end
end
