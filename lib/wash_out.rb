require 'wash_out/engine'
require 'wash_out/param'
require 'wash_out/dispatcher'
require 'wash_out/soap'
require 'wash_out/router'
require 'wash_out/xml_sec'

# php scripts
#require 'wash_out/ws_security_php/soap-wsse.php'
#require 'wash_out/ws_security_php/xmlseclibs.php'
#require 'wash_out/ws_security_php/sign_soap.php'

module ActionDispatch::Routing
  class Mapper
    # Adds the routes for a SOAP endpoint at +controller+.
    def wash_out(controller_name, options={})
      match "#{controller_name}/wsdl" => "#{controller_name}#_generate_wsdl", :via => :get
      match "#{controller_name}/action" => WashOut::Router.new(controller_name), :defaults => { :action => '_action' }
    end
  end
end

Mime::Type.register "application/soap+xml", :soap

ActionController::Renderers.add :soap do |what, options|
  _render_soap(what, options)
end


Mime::Type.register "application/soap+xml", :sign_soap
ActionController::Renderers.add :sign_soap do |what, options|
  _render_sign_soap(what, options)
end

Mime::Type.register "application/soap+xml", :encrypt_soap
ActionController::Renderers.add :encrypt_soap do |what, options|
  _render_encrypt_soap(what, options)
end

Mime::Type.register "application/soap+xml", :sign_encrypt_soap
ActionController::Renderers.add :sign_encrypt_soap do |what, options|
  _render_sign_encrypt_soap(what, options)
end

module ActionView
  class Base
    cattr_accessor :washout_namespace
    @@washout_namespace = false
  end
end

