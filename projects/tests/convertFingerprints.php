<?php

require_once './vendor/autoload.php';

$mitmengine = new laf\Tools\CloudflareMITMEngine;
$mitmengine->convertFromCloudflareFingerprints("./MITMEngineFingerprints/mitm.txt", "./ConvertedFingerprints/mitm.txt"); 
