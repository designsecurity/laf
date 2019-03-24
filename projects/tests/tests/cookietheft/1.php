<?php

$cookie = laf\Detection\CookieTheft::encipher("127.0.0.2");
$detector->getHttprequest()->getRequest()->cookies->set("id", $cookie);

$detector->options->setCookieName("id");



