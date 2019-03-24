<?php

require_once './vendor/autoload.php';

if ($argc > 1) {
    $detector = new Ids\Detector;
    $detector->start();
        
    include($argv[1]);

    $detector->finish();
    
    var_dump($detector->getAlarms());
}
