<?php

namespace Ids\Detection;

class CookieTheft
{ 
    private $detector;
    const PRIVATEKEY = "changeit";
    const IV = "1234567890ABCDEF";
    
    public function __construct($detector)
    {
        $this->detector = $detector; 
    }
    
    public function start()
    {
    }
    
    public function finish()
    {
        $datetime = new \DateTime("now", new \DateTimeZone("Europe/Paris"));
        
        $cookiename = $this->detector->options->getCookieName();
        if(!is_null($cookiename) && !empty($cookiename)) {
            $cipheredcookie = $this->detector->getHttprequest()->getRequest()->cookies->get($cookiename);
            
            $params = array($cipheredcookie);
            $plaintextcookie = call_user_func_array($this->detector->options->getDecryptCookie(), $params);
            
            if(!isset($_SERVER["REMOTE_ADDR"]))
                $_SERVER["REMOTE_ADDR"] = "127.0.0.1";
                
            if($plaintextcookie !== $_SERVER["REMOTE_ADDR"]) {
                $alarm = new \Ids\Alarming\Alarm("identitytheft", "cookie $cookiename ($plaintextcookie) stolen by ".$_SERVER["REMOTE_ADDR"]."", 0, $datetime->format("ymd H:i:s"));
                $this->detector->addAlarm($alarm);
            }
        }
    }
    
    public static function encipher($plaintext) 
    {
        return base64_encode(openssl_encrypt($plaintext, "AES-256-CBC", CookieTheft::PRIVATEKEY, OPENSSL_RAW_DATA, CookieTheft::IV));
    }

    public static function decipher($ciphertext)
    {
        return openssl_decrypt(base64_decode($ciphertext), "AES-256-CBC", CookieTheft::PRIVATEKEY, OPENSSL_RAW_DATA, CookieTheft::IV);
    }
}

