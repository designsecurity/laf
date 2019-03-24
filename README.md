https://support.plesk.com/hc/en-us/articles/213374189-How-to-enable-MySQL-logging- 

- Only reflected XSS

# LAF
> A language application firewall  
> Only PHP is currently supported

[![Build Status](https://travis-ci.org/designsecurity/laf.svg?branch=master)](https://travis-ci.org/designsecurity/laf) [![Packagist](https://img.shields.io/packagist/v/designsecurity/laf.svg)](https://packagist.org/packages/designsecurity/laf) [![Packagist](https://img.shields.io/packagist/l/designsecurity/laf.svg)](LICENSE)
---
## Example
- Embed your code between detector->start() and detector->finish()
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

when yourcode.php contains a simulated XSS attack :
```php
<?php

$detector->getHttprequest()->getRequest()->query->set("vuln", "ee\" onClick=alert('eee') \"boum");
$vulnparam = $detector->getHttprequest()->getRequest()->query->get("vuln");

echo "<a href=\"$vulnparam\"></a>";
```

This alarm is generated :
```javascript
{
  [0]=>
  object(Ids\Alarming\Alarm)#20 (4) {
    ["attack":"Ids\Alarming\Alarm":private]=>
    string(3) "xss"
    ["description":"Ids\Alarming\Alarm":private]=>
    string(38) "in vuln ee" onClick=alert('eee') "boum"
    ["score":"Ids\Alarming\Alarm":private]=>
    int(0)
    ["time":"Ids\Alarming\Alarm":private]=>
    string(15) "190324 14:43:41"
  }
}
```

