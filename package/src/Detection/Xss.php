<?php

namespace laf\Detection;

class Xss
{ 
    private $detector;
    private $keywords;
    
    public function __construct($detector)
    {
        $this->detector = $detector; 
        $this->keywords = [
            "'",
            "\"",
            "<",
            ">"];
    }
    
    public function start()
    {
        if(!ob_get_level())
            ob_start();
    }
    
    public function finish()
    {
        $datetime = new \DateTime("now", new \DateTimeZone("Europe/Paris"));
        $time = $datetime->format("ymd H:i:s");
        
        $page = ob_get_contents();
        $vulnerableParams = $this->detector->getHttprequest()->getVulnerableParamsFromKeywords($this->keywords);
        
        foreach($vulnerableParams as $key => $value) {
            if(strpos($page, $value) !== false) {
                $alarm = new \laf\Alarming\Alarm("xss", "in $key $value", 0, $time);
                $this->detector->addAlarm($alarm);
            }
        }
        //$dom = new \DOMDocument;
        //$dom->loadHTML("e' onClick=alert('e') 'falseparam");
    }
}

