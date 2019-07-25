<?php

namespace laf\Logs;

class Apache
{
    private $logFile;
    private $startDate;
    private $finishDate;
    private $detectionFunction;
    private $regex;
    private $timeZone;
    
    public function __construct()
    {
        $this->logFile = null;
        $this->startDate = null;
        $this->finishDate = null;
        $this->detectionFunction = null;
        $this->regex = null;
        $this->timeZone = new \DateTimeZone("Europe/Paris");
        
        // "[04/Jul/2019:22:04:00 +0000] 127.0.0.1 TLSv1.2 ___ ECDHE-RSA-AES256-GCM-SHA384 ___ '"
        
        // "((.)* ([\d:]+)^4";
    }
    
    public function setRegex($regex)
    {
        $this->regex = $regex;
    }
    
    public function getRegex()
    {
        return $this->regex;
    }
    
    public function setDetectionFunction($detectionFunction)
    {
        $this->detectionFunction = $detectionFunction;
    }
    
    public function getDetectionFunction()
    {
        return $this->detectionFunction;
    }
    
    public function setLogFile($logFile)
    {
        $this->logFile = $logFile;
    }
    
    public function getLogFile()
    {
        return $this->logFile;
    }
    
    public function setStartDate($startDate)
    {
        $this->startDate = $startDate;
    }
    
    public function getStartDate()
    {
        return $this->startDate;
    }
    
    public function setFinishDate($finishDate)
    {
        $this->finishDate = $finishDate;
    }
    
    public function getFinishDate()
    {
        return $this->finishDate;
    }
    
    public function setTimeZone($timezone)
    {
        $this->timeZone = $timezone;
    }
    
    public function getTimeZone()
    {
        return $this->timeZone;
    }
    
    public function parseLogs($detector)
    {
        if(!file_exists($this->logFile)) {
            echo "file = '".$this->logFile."' doesn't exist\n";
            return;
        }
        
        if(is_null($this->regex)) {
            echo "regex to parse Apache logs is not set\n";
            return;
        }
        
        $fp = fopen($this->logFile, "r");
        if(!$fp) {
            echo "fail to open file = '".$this->logFile."'\n";
            return;
        }
        
        $user = null;
        $database = null;
        $datetime = null;
        
        $detectionFunction = $this->getDetectionFunction();
                
        while(($line = fgets($fp)) !== false) {
            if(preg_match($this->regex, $line, $matches)) {
                
                $datetime = \DateTime::createFromFormat("d/M/Y:H:i:s O", $matches[1], $this->timeZone);

                if(!is_null($datetime)
                    && $datetime > $this->getStartDate() 
                        && $datetime <= $this->getFinishDate()) {
                        
                    $params = array($detector, $datetime->format("ymd H:i:s"), $matches[2], $matches[5]);
                    call_user_func_array($detectionFunction, $params);
                }
            }
        }
        
        fclose($fp);
    }
}
