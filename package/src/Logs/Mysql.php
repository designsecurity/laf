<?php

namespace laf\Logs;

/*
/etc/myc.cnf

[mysqld]
general_log     = on
general_log_file = /var/log/mysql/queries.log
*/

class Mysql
{
    private $logFile;
    private $startDate;
    private $finishDate;
    private $detectionFunction;
    
    public function __construct()
    {
        $this->logFile = null;
        $this->startDate = null;
        $this->finishDate = null;
        $this->detectionFunction = null;
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
    
    public function parseGeneralLogs($detector, $vulnerableParams = null)
    {
        if(!file_exists($this->logFile)) {
            echo "file = '".$this->logFile."' doesn't exist\n";
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
                
        if(!is_null($vulnerableParams) && count($vulnerableParams) > 0) {
            $detectionFunction = $this->getDetectionFunction();
            
            while(($line = fgets($fp)) !== false) {
                if(preg_match("/^(\d{6}\s+[\d:]+)\s+(\d+)\s+(Query|Execute|Connect|Init|Change)/", $line, $matches)) {
                
                    $datetime = \DateTime::createFromFormat("ymd H:i:s", $matches[1], new \DateTimeZone("Europe/Paris"));
                    
                    if($datetime !== false) {
                        
                        $cid = $matches[2];
                        $cmd = $matches[3];
                        
                        if($cmd === "Connect") {
                            if(preg_match("/Connect\s+(.+) on (\w*)/", $line, $matches)
                                || preg_match("/Connect\s+([.^\s]+)/", $line, $matches)) {
                                
                                $user = $matches[1];
                                $database = isset($matches[2]) ? $matches[2] : null;
                            }
                        }
                    }
                }
                else if(preg_match("/^\s+(\d+)\s+Query\s+(.+)/", $line, $matches) 
                    && !is_null($user) 
                        && !is_null($datetime)
                            && $datetime > $this->getStartDate() 
                                && $datetime <= $this->getFinishDate())
                {
                    $cid = $matches[1];
                    $query = $matches[2];
                                
                    if(preg_match("/^.*SELECT(.+)FROM(.+)/i", $query, $matches)
                        || preg_match("/^DELETE(.+)FROM(.+)/i", $query, $matches)
                            || preg_match("/^INSERT(.+)INTO(.+)/i", $query, $matches)
                                || preg_match("/^UPDATE(.+)SET(.+)/i", $query, $matches)) {
                                
                        foreach($vulnerableParams as $key => $value) 
                        {
                            $params = array($detector, $query, $key, $value, $datetime->format("ymd H:i:s"));
                            call_user_func_array($detectionFunction, $params);
                        }
                    }
                }
            }
        }
        
        fclose($fp);
    }
}
