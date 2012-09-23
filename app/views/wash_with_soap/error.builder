xml.instruct!
xml.tag! "soap:Envelope", "xmlns:soap" => 'http://schemas.xmlsoap.org/soap/envelope/',
             "xmlns:xsi" => 'http://www.w3.org/2001/XMLSchema-instance',
             "xmlns:tns" => @namespace do
  xml.tag! "soap:Body" do
    xml.tag! "tns:Fault", :encodingStyle => 'http://schemas.xmlsoap.org/soap/encoding/' do
      xml.tag! "tns:faultcode", "Server", 'xsi:type' => 'xsd:QName'    
      xml.tag! "tns:faultstring", error_message, 'xsi:type' => 'xsd:string'
    end
  end
end
