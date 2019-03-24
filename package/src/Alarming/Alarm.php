<?php

namespace laf\Alarming;

class Alarm
{ 
    private $attack;
    private $description;
    private $score;
    private $time;
    
    public function __construct($attack, $description, $score, $time)
    {
        $this->attack = $attack;
        $this->description = $description;
        $this->score = 0;
        $this->time = $time;
    }
    
    public function setTime($time)
    {
        $this->time = $time;
    }
    
    public function getTime()
    {
        return $this->time;
    }
    
    public function setScore($score)
    {
        $this->score = $score;
    }
    
    public function getScore()
    {
        return $this->score;
    }
    
    public function setDescription($description)
    {
        $this->description = $description;
    }
    
    public function getDescription()
    {
        return $this->description;
    }
    
    public function setAttack($attack)
    {
        $this->attack = $attack;
    }
    
    public function getAttack()
    {
        return $this->attack;
    }
    
    public function toString()
    {
        return $this->attack." detected at ".$this->time." (score = ".$this->score.") : ".$this->description;
    }
}

