# laf
> A language application firewall  
> Only PHP is currently supported

[![Build Status](https://travis-ci.org/designsecurity/laf.svg?branch=master)](https://travis-ci.org/designsecurity/laf) [![Packagist](https://img.shields.io/packagist/v/designsecurity/laf.svg)](https://packagist.org/packages/designsecurity/laf) [![Packagist](https://img.shields.io/packagist/l/designsecurity/laf.svg)](LICENSE)
---
## Example
- Embed your code between $detector->start() and $detector->finish()
- If attacks are detected, alarms are generated and can be retrieved with $detector->getAlarms()

```php
<?php
    $detector = new Ids\Detector;
    $detector->start();
        
    include("yourcode.php");

    $detector->finish();
    
    var_dump($detector->getAlarms());
?>
```

when yourcode.php is vulnerable to an attack (in this example a simulated XSS attack) :
```php
<?php

$detector->getHttprequest()->getRequest()->query->set("vuln", "ee\" onClick=alert('eee') \"boum");
$vulnparam = $detector->getHttprequest()->getRequest()->query->get("vuln");

echo "<a href=\"$vulnparam\"></a>";
```

this alarm is generated :
```javascript
{
  [0]=>
  object(laf\Alarming\Alarm)#24 (4) {
    ["attack":"laf\Alarming\Alarm":private]=>
    string(3) "xss"
    ["description":"laf\Alarming\Alarm":private]=>
    string(38) "in vuln ee" onClick=alert('eee') "boum"
    ["score":"laf\Alarming\Alarm":private]=>
    int(0)
    ["time":"laf\Alarming\Alarm":private]=>
    string(15) "190725 09:19:13"
  }
}
```

