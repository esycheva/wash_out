require 'nori'

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

      params = Nori.parse(request.body.read)


      unless params[:envelope][:body][:encrypted_data].blank?
	      request.body.rewind
        params = Nori.parse(XMLSec.decode(request.body.read, WS_SECURITY_SETTINGS["private_key"], WS_SECURITY_SETTINGS["cert"]))
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
        render_soap_error("php_script_error")
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
      render :template => 'wash_with_soap/error', :status => 500,
             :locals => { :error_message => message }
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

      # read the output of a program
      result = ''
      IO.popen("echo \"#{soap_response_str}\" | #{php_script_file} #{private_key_path} #{cert_path} #{client_cert_path} #{options[:ws_security]}" ) do |readme|
        while s = readme.gets do
          result = result + s
        end
      end
      result
    end

    def is_exception?(result)
      !result.scan("exception").blank?
    end
  end
end
