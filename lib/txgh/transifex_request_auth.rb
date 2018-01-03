require 'openssl'

module Txgh
  class TransifexRequestAuth
    HMAC_DIGEST_256 = OpenSSL::Digest.new('sha256')
    TRANSIFEX_HEADER = 'HTTP_X_TX_SIGNATURE_V2' #'X-TX-Signature-V2'
    DATE_HEADER = 'HTTP_DATE'
    URL_HEADER = 'HTTP_X_TX_URL'

    class << self
      def authentic_request?(request, secret)
        request.body.rewind
        content = request.body.read

        http_verb = 'POST' #TODO Use verb from request
        http_date = request.env[DATE_HEADER]
        url = request.env[URL_HEADER]
        content_md5 = Digest::MD5.hexdigest content

        data = [http_verb, url, http_date, content_md5].join("\n")
        expected_signature = digest(data, secret)
        actual_signature = request.env[TRANSIFEX_HEADER]
        actual_signature == expected_signature
      end


      private

      def digest(data, secret)
        Base64.encode64(
          OpenSSL::HMAC.digest(HMAC_DIGEST_256, secret, data)
        ).strip
      end
    end
  end
end
