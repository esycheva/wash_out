#!/usr/bin/php -q
<?php
require('soap-wsse.php');

$private_key = $argv[1];
$cert_file = $argv[2];
$service_cert = $argv[3];

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
$objKey->loadKey($private_key, TRUE);

/* Sign the message - also signs appropraite WS-Security items */
$options = array("insertBefore" => FALSE);
$objWSSE->signSoapDoc($objKey, $options);
        
/* Add certificate (BinarySecurityToken) to the message */
$token = $objWSSE->addBinaryToken(file_get_contents($cert_file));
        
/* Attach pointer to Signature */
$objWSSE->attachTokentoSig($token);

$objKey = new XMLSecurityKey(XMLSecurityKey::AES128_CBC);
$objKey->generateSessionKey();
        
$siteKey = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type'=>'public'));
$siteKey->loadKey($service_cert, TRUE, TRUE);
        
$options = array("KeyInfo" => array("X509SubjectKeyIdentifier" => true));
$objWSSE->encryptSoapDoc($siteKey, $objKey, $options);
        

/* returns signed document to STDOUT*/
echo $objWSSE->saveXML();

