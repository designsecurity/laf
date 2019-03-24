<?php

$detector->getHttprequest()->getRequest()->query->set("vuln", "1' OR 1=1");
$vulnparam = $detector->getHttprequest()->getRequest()->query->get("vuln");

$db = new mysqli("localhost", "root", "root", "test");
$db->query("select * from table where id = '$vulnparam'"); 
$db->close();


