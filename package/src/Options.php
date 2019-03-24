<?php

namespace Ids;

class Options
{ 
    private $decryptcookie;
    private $cookiename;
    
    public function __construct()
    {
        $this->cookiename = "";
        $this->decryptcookie = "Ids\Detection\CookieTheft::decipher";
    }
    
    public function setCookieName($cookiename)
    {
        $this->cookiename = $cookiename;
    }
    
    public function getCookieName()
    {
        return $this->cookiename;
    }
    
    public function setDecryptCookie($decryptcookie)
    {
        $this->decryptcookie = $decryptcookie;
    }
    
    public function getDecryptCookie()
    {
        return $this->decryptcookie;
    }
}
