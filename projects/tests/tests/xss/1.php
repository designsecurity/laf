<?php

$detector->getHttprequest()->getRequest()->query->set("vuln", "ee\" onClick=alert('eee') \"boum");
$vulnparam = $detector->getHttprequest()->getRequest()->query->get("vuln");

echo "<a href=\"$vulnparam\"></a>";



