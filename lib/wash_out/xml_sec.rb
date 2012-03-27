require 'rubygems'
require "rexml/document"
require "rexml/xpath"
require "openssl"
require "xmlcanonicalizer"
require "digest/sha1"


module XMLSec
  # decode
  def self.decrypt(xml_str, private_key_path, cert_path)
    doc = REXML::Document.new(xml_str)

    cert = OpenSSL::X509::Certificate.new(File.read(cert_path))
    private_key = OpenSSL::PKey::RSA.new(File.read(private_key_path))

    subject_key_id_element = REXML::XPath.first(doc, "//wsse:KeyIdentifier")

    if subject_key_id_element.blank?
      raise WashOut::Dispatcher::SOAPError, "The Subject Key Element is blank."
    else
      subject_key_id = subject_key_id_element.text
    end

    subject_key_id.gsub!(/\n/m, '')
    subject_key_id.gsub!(/\s/, '')

    cert_subject_key_id = Digest::SHA1.base64digest cert.public_key.to_der

    unless subject_key_id == cert_subject_key_id
      raise WashOut::Dispatcher::SOAPError, "The Subject Key Element is bad."
    end

    unless cert.check_private_key(private_key)
      raise WashOut::Dispatcher::SOAPError, "The Certificate error."
    end

    c1 = REXML::XPath.first(doc, '//xenc:EncryptedKey//xenc:CipherValue', 'xenc' => 'http://www.w3.org/2001/04/xmlenc#')

    encrypted_data_uri = []

    REXML::XPath.each(doc, '//xenc:EncryptedKey//xenc:DataReference', 'xenc' => 'http://www.w3.org/2001/04/xmlenc#') do |ref|
      encrypted_data_uri << ref.attributes.get_attribute("URI").value.gsub!(/\#/, '')
    end

    # Generate the key used for the cipher below via the RSA::OAEP algo
    rsak      = RSA::Key.new private_key.n, private_key.d
    v1s       = Base64.decode64(c1.text)
    begin
      cipherkey = RSA::OAEP.decode rsak, v1s
    rescue RSA::OAEP::DecodeError
      raise WashOut::Dispatcher::SOAPError, "The decrypt error."
    end

    encrypted_data_uri.each do |uri|
      # The aes-128-cbc cipher has a 128 bit initialization vector (16 bytes)
      # and this is the first 16 bytes of the raw string.
      encrypted_data = REXML::XPath.first(doc, "//xenc:EncryptedData[@Id=\"#{uri}\"]")
      c =  REXML::XPath.first(doc, "//xenc:EncryptedData[@Id=\"#{uri}\"]//xenc:CipherValue")
      bytes  = Base64.decode64(c.text).bytes.to_a
      iv     = bytes[0...16].pack('c*')
      others = bytes[16..-1].pack('c*')

      cipher = OpenSSL::Cipher.new('aes-128-cbc')
      cipher.decrypt
      cipher.iv  = iv
      cipher.key = cipherkey

      out = cipher.update(others)

      # The encrypted string's length might not be a multiple of the block
      # length of aes-128-cbc (16), so add in another block and then trim
      # off the padding. More info about padding is available at
      # http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html in
      # Section 5.2
      out << cipher.update("\x00" * 16)
      padding = out.bytes.to_a.last
      result_doc = doc.class.new(out[0..-(padding + 1)])
      doc.root.insert_after encrypted_data, result_doc.root
    end
    doc.to_s
  end

  # verify_sign
  def self.verify_sign(str)
    doc = REXML::Document.new(str)
    base64_cert = doc.elements["//wsse:BinarySecurityToken"].text
    cert_text               = Base64.decode64(base64_cert)
    cert                    = OpenSSL::X509::Certificate.new(cert_text)
    # validate references

    # remove signature node
    sig_element = REXML::XPath.first(doc, "//ds:Signature", {"ds"=>"http://www.w3.org/2000/09/xmldsig#"})
    return false unless sig_element
    sig_element.remove

    #check digests
    REXML::XPath.each(sig_element, "//ds:Reference", {"ds"=>"http://www.w3.org/2000/09/xmldsig#"}) do | ref |
      uri                   = ref.attributes.get_attribute("URI").value
      hashed_element        = REXML::XPath.first(doc, "//[@wsu:Id=\"#{uri[1,uri.size]}\"]")
      puts hashed_element
      canoner               = XML::Util::XmlCanonicalizer.new(false, true)

      canon_hashed_element  = canoner.canonicalize(hashed_element)
      hash                  = Base64.encode64(Digest::SHA1.digest(canon_hashed_element)).chomp
      digest_value          = REXML::XPath.first(ref, "//ds:DigestValue", {"ds"=>"http://www.w3.org/2000/09/xmldsig#"}).text
      valid_flag            = hash == digest_value
      puts valid_flag
      return valid_flag if !valid_flag
    end

    # verify signature
    canoner                 = XML::Util::XmlCanonicalizer.new(false, true)
    signed_info_element     = REXML::XPath.first(sig_element, "//ds:SignedInfo")
    canon_string            = canoner.canonicalize(signed_info_element)
    base64_signature        = REXML::XPath.first(sig_element, "//ds:SignatureValue").text
    signature               = Base64.decode64(base64_signature)

    # get certificate object
    valid_flag              = cert.public_key.verify(OpenSSL::Digest::SHA1.new, signature, canon_string)
    valid_flag
  rescue
    false
  end

end
