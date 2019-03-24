<?php

require_once './vendor/autoload.php';
use PHPUnit\Framework\TestCase;

class RunTest extends TestCase
{
    /**
     * @dataProvider dataProvider
     */
    public function testSecurity($file, $expectedAlarms)
    {
        $detector = new laf\Detector;
        $detector->start();
        
        include($file);

        $detector->finish();
        
        $this->assertCount(count($expectedAlarms), $detector->getAlarms());
        $i = 0;
        if($detector->hasAlarms()) {
            foreach($detector->getAlarms() as $alarm) {
                if(isset($expectedAlarms[$i])) {
                    $this->assertEquals($expectedAlarms[$i][0], $alarm->getAttack());
                    $this->assertContains($expectedAlarms[$i][1], $alarm->getDescription());
                }
                
                $i ++;
            }
        }
    }

    public function dataProvider()
    {
        $data = [
            [
                "./tests/xss/1.php",
                [["xss", "onClick=alert('eee')"]]
            ],
            [
                "./tests/sqli/1.php",
                [["sqlinjection", "1' OR 1=1"]]
            ],
            [
                "./tests/cookietheft/1.php",
                [["identitytheft", "cookie id (127.0.0.2) stolen by "]]
            ]
        ];
        
        return $data;
    }
}
