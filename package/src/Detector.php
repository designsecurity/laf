<?php

namespace laf;

class Detector
{ 
    public $options;
    
    private $sqlinjection;
    private $xss;
    private $cookietheft;
    private $tlsmitm;
    private $httprequest;
    private $alarms;
    private $configurationFile;
    
    public function __construct()
    {
        $this->alarms = [];
        $this->httprequest = new \laf\Http\Request;
        
        $this->sqlinjection = new \laf\Detection\SqlInjection($this);
        $this->xss = new \laf\Detection\Xss($this);
        $this->cookietheft = new \laf\Detection\CookieTheft($this);
        $this->tlsmitm = new \laf\Detection\TLSmitm($this);
        $this->tlsmitm->loadMitmFromFile(dirname(__FILE__)."/Detection/MITMfingerprints/additions.txt");
        $this->tlsmitm->loadMitmFromFile(dirname(__FILE__)."/Detection/MITMfingerprints/mitm.txt");
        
        $this->options = new Options;
        $this->configurationFile = null;
    }
    
    public function getTLSmitm()
    {
        return $this->tlsmitm;
    }
    
    public function addAlarm($alarm)
    {
        $this->alarms[] = $alarm;
    }
    
    public function hasAlarms()
    {
        return count($this->alarms);
    }
    
    public function getAlarms()
    {
        return $this->alarms;
    }
    
    public function start()
    {
        $this->sqlinjection->start();
        $this->xss->start();
        $this->cookietheft->start();
        $this->tlsmitm->start();
    }
    
    public function finish()
    {
        $this->sqlinjection->finish();
        $this->xss->finish();
        $this->cookietheft->finish();
        $this->tlsmitm->finish();
    }
    
    public function getHttprequest()
    {
        return $this->httprequest;
    }
    
    public function readOptions($file)
    {
        try {
            if (file_exists($file)) {
                $yaml = new Parser();
                $value = $yaml->parse(file_get_contents($file));

                if (is_array($value)) {
                    if (isset($value["options"])) {
                        if (isset($value["options"]["setDecryptCookie"])) {
                            $this->options->setDecryptCookie($value["options"]["setDecryptCookie"]);
                        }
                        
                        if (isset($value["options"]["setCookieName"])) {
                            $this->options->setCookieName($value["options"]["setCookieName"]);
                        }
                    }
                }
            }
        } catch (ParseException $e) {
            throw new \Exception(Lang::UNABLE_TO_PARSER_YAML);
        }
    }
}

