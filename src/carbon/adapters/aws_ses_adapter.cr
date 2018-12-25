require "http"
require "json"

class Carbon::AwsSesAdapter < Carbon::Adapter
  private getter key : String
  private getter secret : String
  private getter region : String
  private getter? sandbox : Bool

  def initialize(@key, @secret, @region, @sandbox = false)
  end

  def deliver_now(email : Carbon::Email)
    Carbon::AwsSesAdapter::Email.new(email, key, secret, region, sandbox?).deliver
  end

  class Email
    MAIL_SEND_PATH = "/"
    private getter email, key, secret, region, base_uri
    private getter? sandbox : Bool

    def initialize(@email : Carbon::Email, @key : String, @secret : String, @region : String, @sandbox = false)
      @base_uri = "email.#{@region}.amazonaws.com"
      @date = Tine.utc_now.to_s("%y%m%dT%H%M%SZ")
      @content_type = "application/x-www-form-urlencoded"
      @service = "ses"
      @algorithm = "AWS4-HMAC-SHA256"
      @signed_headers = "content-type;host;x-amz-date"
      @credential_scope = "#{@date.split("T")[0]}/#{@region}/#{@service}/aws4_request"
    end

    def deliver
      client.post(MAIL_SEND_PATH, body: params).tap do |response|
        unless response.success?
          raise JSON.parse(response.body).inspect
        end
      end
    end

    def params
      param_string = "Action=SendEmail"
      param_string += "&Source=#{URI.escape(email.from.address)}"

      email.to.each_with_index(1) do |to_address, idx|
        param_string += "&Destination.ToAddresses.member.#{idx}=#{URI.escape(to_address)}"
      end

      email.cc.each_with_index(1) do |cc_address, idx|
        param_string += "&Destination.CcAddresses.member.#{idx}=#{URI.escape(cc_address)}"
      end

      email.bcc.each_with_index(1) do |bcc_address, idx|
        param_string += "&Destination.BccAddresses.member.#{idx}=#{URI.escape(bcc_address)}"
      end

      param_string += "&Message.Subject.Data=#{URI.escape(email.subject)}"
      param_string += "&Message.Body.Text.Data=#{URI.escape(email.text_body)}" if email.text_body && !email.text_body.empty?
      param_string += "&Message.Body.Html.Data=#{URI.escape(email.html_body)}" if email.html_body && !email.html_body.empty?
      param_string += "&ReplyToAddresses.member.1=#{URI.escape(reply_to_address)}" if reply_to_address && !reply_to_address.empty?

      param_string
    end

    private def reply_to_address : String?
      reply_to_header.values.first?
    end

    private def reply_to_header
      reply_to_header = email.headers.select do |key, value|
        key.downcase == "reply-to"
      end
    end

    private def headers : Hash(String, String)
      email.headers.reject do |key, value|
        key.downcase == "reply-to"
      end
    end

    private def authorization : String
      signature = OpenSSL::HMAC(:sha256, k_signing, m_signing)
      "#{@algorithm} Credential=#{@key}/#{@credential_scope}, SignedHeaders=#{@signed_headers}, Signature=#{signature}"
    end

    private def k_signing : String
      k_secret = @secret
      k_date = OpenSSL::HMAC(:sha256, "AWS4#{k_secret}", @date)
      k_region = OpenSSL::HMAC(:sha256, k_date, @region)
      k_service = OpenSSL::HMAC(:sha256, k_region, @service)
      k_signing = OpenSSL::HMAC(:sha256, k_service, "aws4_request")
    end

    private def m_signing : String
      m_signing = "#{@algorithm}\n"
      m_signing += "#{@date}\n"
      m_signing += "#{@credential_scope}\n"
      m_signing += "#{Digest::Base.digest(canonical_string)}"
    end

    private def canonical_string : String
      canonical_string = "POST\n"
      canonical_string += "#{MAIL_SEND_PATH}\n"
      canonical_string += "content-type:#{@content_type}\n"
      canonical_string += "host:#{@base_uri}\n"
      canonical_string += "x-amz-date:#{@date}\n"
      canonical_string += "#{@signed_headers}\n"
      canonical_string += "#{Digest::Base.digest(params)}\n"
    end

    @_client : HTTP::Client?

    private def client : HTTP::Client
      @_client ||= HTTP::Client.new(@base_uri, port: 443, tls: true).tap do |client|
        client.before_request do |request|
          request.headers["X-Amz-Date"] = @date
          request.headers["Content-Type"] = @content_type
          request.headers["Host"] = @base_uri
          request.headers["Authorization"] = "#{authorization}"
        end
      end
    end
  end
end
