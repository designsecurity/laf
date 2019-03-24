<?php

namespace laf\Http;

class Request
{
    private $request;
    
    public function __construct()
    {
        $this->request = $this->request = \Symfony\Component\HttpFoundation\Request::createFromGlobals();
    }
    
    public function getRequest()
    {
        return $this->request;
    }
    
    public function getVulnerableParamsFromKeywords($keywords)
    {
        $parametersVulnerable = [];
        $parametersPost = $this->request->request->keys();
        foreach($parametersPost as $key) {
            foreach($keywords as $keyword) {
                if(strpos(strtoupper($this->request->request->get($key)), $keyword) !== false)
                    $parametersVulnerable[$key] = $this->request->request->get($key);
            }
        }
        
        $parametersGet = $this->request->query->keys();
        foreach($parametersGet as $key) {
            foreach($keywords as $keyword) {
                if(strpos(strtoupper($this->request->query->get($key)), $keyword) !== false)
                    $parametersVulnerable[$key] = $this->request->query->get($key);
            }
        }
        
        return $parametersVulnerable;
    }
}
