require 'nori'
require 'openssl'

module WashOut
  # The WashOut::Dispatcher module should be included in a controller acting
  # as a SOAP endpoint. It includes actions for generating WSDL and handling
  # SOAP requests.
  module Dispatcher
    # Default Type namespace
    NAMESPACE = 'urn:WashOut'

    # A SOAPError exception can be raised to return a correct SOAP error
    # response.
    class SOAPError < Exception; end

    # This filter parses the SOAP request and puts it into +params+ array.
    def _parse_soap_parameters
      soap_action = request.env['wash_out.soap_action']
      action_spec = self.class.soap_actions[soap_action]

      # Do not interfere with project-space Nori setup
      strip   = Nori.strip_namespaces?
      convert = Nori.convert_tags?
      Nori.strip_namespaces = true
      Nori.convert_tags_to { |tag| tag.snakecase.to_sym }
	
      body = request.body.read
      params = Nori.parse(body)

      request_doc = REXML::Document.new(body)
      sign_els = REXML::XPath.first(request_doc, "//ds:Signature", {"ds"=>"http://www.w3.org/2000/09/xmldsig#"})

      unless sign_els.blank?
        render_soap_error('The signature is invalid.') unless XMLSec.verify_sign(body)
      end
	
      encrypted_elements = REXML::XPath.match(request_doc, "//xenc:EncryptedData", 'xenc' => 'http://www.w3.org/2001/04/xmlenc#')

      unless encrypted_elements.blank?
        begin
	  decrypted_request = XMLSec.decrypt(body, WS_SECURITY_SETTINGS["private_key"], WS_SECURITY_SETTINGS["cert"])
        rescue => e
          render_soap_error(e.message)
        end
	decrypted_doc = REXML::Document.new decrypted_request
	sign_els = REXML::XPath.first(decrypted_doc, "//ds:Signature", {"ds"=>"http://www.w3.org/2000/09/xmldsig#"})

        unless sign_els.blank?
          render_soap_error('The signature is invalid.') unless XMLSec.verify_sign(decrypted_request)
        end

        params = Nori.parse(decrypted_request)
      end	

      xml_data = params[:envelope][:body][soap_action.underscore.to_sym] || {}

      strip_empty_nodes = lambda{|hash|
        hash.each do |key, value|
          if value.is_a? Hash
            value = value.delete_if{|key, value| key.to_s[0] == '@'}

            if value.length > 0
              hash[key] = strip_empty_nodes.call(value)
            else
              hash[key] = nil
            end
          end
        end

        hash
      }

      xml_data = strip_empty_nodes.call(xml_data)

      # Reset Nori setup to project-space
      Nori.strip_namespaces = strip
      Nori.convert_tags_to convert

      @_params = HashWithIndifferentAccess.new

      action_spec[:in].each do |param|
        @_params[param.name] = param.load(xml_data, param.name.to_sym)
      end
    end

    # This action generates the WSDL for defined SOAP methods.
    def _generate_wsdl
      @map       = self.class.soap_actions
      @namespace = NAMESPACE
      @name      = controller_path.gsub('/', '_')

      render :template => 'wash_with_soap/wsdl'
    end

    # Render a SOAP response.
    def _render_soap(result, options)
      @namespace  = NAMESPACE
      @operation  = soap_action = request.env['wash_out.soap_action']
      action_spec = self.class.soap_actions[soap_action][:out].clone
      result = { 'value' => result } unless result.is_a? Hash
      result = HashWithIndifferentAccess.new(result)
      inject = lambda {|data, spec|
        spec.each do |param|
          if param.struct?
            inject.call(data[param.name], param.map)
          else
            param.value = data[param.name]
          end
        end
      }

      soap_response = render_to_string :template => 'wash_with_soap/response',
             :locals => { :result => inject.call(result, action_spec) }

      if options[:ws_security] == "encrypt" || options[:ws_security] == "sign" || options[:ws_security] == "sign_encrypt"
        soap_response = ws_security_apply(soap_response, options)
      end
      


      if is_exception?(soap_response)
        Rails.logger.error "PHP_SCRIPT_ERROR #{ws_security_response}"
        render :template => 'wash_with_soap/error', :status => 500,
             :locals => { :error_message => "php_script_error" }
      else
          render :xml => soap_response
      end
    end

    # This action is a fallback for all undefined SOAP actions.
    def _invalid_action
      render_soap_error("Cannot find SOAP action mapping for #{request.env['wash_out.soap_action']}")
    end

    # Render a SOAP error response.
    #
    # Rails do not support sequental rescue_from handling, that is, rescuing an
    # exception from a rescue_from handler. Hence this function is a public API.
    def render_soap_error(message, options = {})
      @namespace = NAMESPACE
      soap_error_response = render_to_string :template => 'wash_with_soap/error', :status => 500,
             :locals => { :error_message => message }

      if options[:ws_security] == "encrypt" || options[:ws_security] == "sign" || options[:ws_security] == "sign_encrypt"
        soap_error_response = ws_security_apply(soap_error_response, options)
      end

      render :xml => soap_error_response
    end


    private

    def self.included(controller)
      controller.send :rescue_from, SOAPError, :with => :_render_soap_exception
      controller.send :helper, :wash_out
      controller.send :before_filter, :_parse_soap_parameters, :except => [ :_generate_wsdl, :_invalid_action ]
    end

    def _render_soap_exception(error)
      render_soap_error(error.message)
    end

    def ws_security_apply(soap_response_str, options)
      # processing soap response
      soap_response_str.gsub!(/\n/m, '\n')
      soap_response_str.gsub!(/"/, '\"')

      # php script path
      mydir = File.dirname(__FILE__)
      php_script_file = mydir + "/ws_security_php/ws_security.php"

      # keys filename from rails_app/config/*.yml
      private_key_path = WS_SECURITY_SETTINGS["private_key"]
      cert_path = WS_SECURITY_SETTINGS["cert"]
      client_cert_path = WS_SECURITY_SETTINGS["client_cert"]

      # add X509v3 Subject Key Identifier extension to client certificate
      cert_string = cert_str(client_cert_path)
      write(client_cert_path)

      # read the output of a program
      result = ''
      IO.popen("echo \"#{soap_response_str}\" | #{php_script_file} #{private_key_path} #{cert_path} #{client_cert_path} #{options[:ws_security]}" ) do |readme|
        while s = readme.gets do
          result = result + s
        end
      end
      result
    end

    # return cert string with extension
    def self.cert_str(path_to_cert)
      c = OpenSSL::X509::Certificate.new( File.read path_to_cert)
      ef = OpenSSL::X509::ExtensionFactory.new(nil, c)
      c.add_extension(ef.create_extension 'subjectKeyIdentifier', 'hash')
      c.to_pem
    end	
    
    # write to file
    def self.write(pem_str, output_filename)
      File.open(output_filename, 'w:windows-1251'){|file| file.write pem_str}
    end 

    def is_exception?(result)
      !result.scan("exception").blank?
    end
  end
end
