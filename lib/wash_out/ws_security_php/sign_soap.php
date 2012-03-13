#!/usr/bin/php -q
<?php
require('soap-wsse.php');

define('PRIVATE_KEY', '/home/lena/Documents/soap/test.pem');
define('CERT_FILE', '/home/lena/Documents/soap/test.crt');
define('SERVICE_CERT', '/home/lena/Documents/soap/test.crt');

/* Read from stdin */
$text = '';
$in = fopen('php://stdin', 'r');
while(!feof($in)){
    $text = $text . fread($in, 4096);
}
fclose($in);


$doc = new DOMDocument;
$doc->loadXML($text);

$objWSSE = new WSSESoap($doc);
        
/* create new XMLSec Key using AES128_CBC and type is private key */
$objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type'=>'private'));
        
/* load the private key from file - last arg is bool if key in file (TRUE) or is string (FALSE) */
$objKey->loadKey(PRIVATE_KEY, TRUE);
        
/* Sign the message - also signs appropraite WS-Security items */
$options = array("insertBefore" => FALSE);
$objWSSE->signSoapDoc($objKey, $options);
        
/* Add certificate (BinarySecurityToken) to the message */
$token = $objWSSE->addBinaryToken(file_get_contents(CERT_FILE));
        
/* Attach pointer to Signature */
$objWSSE->attachTokentoSig($token);

/* returns signed document to STDOUT*/
echo $objWSSE->saveXML();

