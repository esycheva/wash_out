require 'rubygems'
require "rexml/document"
require "rexml/xpath"
require "openssl"
require "xmlcanonicalizer"
require "digest/sha1"

module XMLSec
  def self.decode(xml_str, private_key_path, cert_path)	
    doc = REXML::Document.new(xml_str)

    cert = OpenSSL::X509::Certificate.new(File.read(cert_path))
    private_key = OpenSSL::PKey::RSA.new(File.read(private_key_path))

    subject_key_id_element = REXML::XPath.first(doc, "//wsse:KeyIdentifier")

    if subject_key_id_element.blank?
      return false
    else
      subject_key_id = subject_key_id_element.text
    end

    subject_key_id.gsub!(/\n/m, '')
    subject_key_id.gsub!(/\s/, '')

    cert_subject_key_id = Digest::SHA1.base64digest cert.public_key.to_der

    unless subject_key_id == cert_subject_key_id
      return false
    end

    unless cert.check_private_key(private_key)
      return false
    end

    c1, c2 = REXML::XPath.match(doc, '//xenc:CipherValue', 'xenc' => 'http://www.w3.org/2001/04/xmlenc#')

    # Generate the key used for the cipher below via the RSA::OAEP algo
    rsak      = RSA::Key.new private_key.n, private_key.d
    v1s       = Base64.decode64(c1.text)
    begin
      cipherkey = RSA::OAEP.decode rsak, v1s
    rescue RSA::OAEP::DecodeError
      return false
    end

    # The aes-128-cbc cipher has a 128 bit initialization vector (16 bytes)
    # and this is the first 16 bytes of the raw string.
    bytes  = Base64.decode64(c2.text).bytes.to_a
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
    decrypted_data_doc = doc.class.new(out[0..-(padding + 1)])

    doc.root.elements.delete("//xenc:EncryptedKey")
    doc.root.insert_before("//xenc:EncryptedData", decrypted_data_doc.root)
    doc.root.elements.delete("//xenc:EncryptedData")

    # Returns the xml string.
    doc.to_s
  end
end
