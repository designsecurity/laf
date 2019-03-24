<?php

namespace laf\Detection;

class SqlInjection
{ 
    private $mysqlParser;
    private $detector;
    private $keywords;
    
    public function __construct($detector)
    {
        $this->mysqlParser = null;
        $this->detector = $detector;
        $this->keywords = [
            "ALTER",
            "ANALYZE",
            "AND",
            "AUTO_INCREMENT",
            "BEFORE",
            "BETWEEN",
            "BIGINT",
            "BINARY",
            "COLLATE",
            "COLUMN",
            "DATABASE",
            "DISTINCT",
            "DROP",
            "EACH",
            "ELSE",
            "ELSEIF",
            "EMPTY",
            "EXCEPT",
            "EXISTS",
            "EXIT",
            "FETCH",
            "FIRST_VALUE",
            "FOREIGN",
            "FROM",
            "GROUP",
            "GROUPING",
            "GROUPS",
            "GROUP_REPLICATION",
            "INDEX",
            "INFILE",
            "INSERT",
            "INTEGER",
            "INTERVAL",
            "INTO",
            "JOIN",
            "KEY_BLOCK_SIZE",
            "LIKE",
            "LIMIT",
            "LOCALTIME",
            "LOCALTIMESTAMP",
            "LONGBLOB",
            "LONGTEXT",
            "MAXVALUE",
            "MAX_CONNECTIONS_PER_HOUR",
            "MAX_QUERIES_PER_HOUR",
            "MAX_ROWS",
            "MAX_SIZE",
            "MAX_UPDATES_PER_HOUR",
            "MAX_USER_CONNECTIONS",
            "MEDIUMBLOB",
            "MEDIUMINT",
            "MEDIUMTEXT",
            "NUMERIC",
            "NVARCHAR",
            "OPTIONS",
            "OR",
            "ORDER",
            "OUTER",
            "OUTFILE",
            "PATH",
            "PERCENT_RANK",
            "PERSIST",
            "PERSIST_ONLY",
            "REPLICATE_DO_DB",
            "REPLICATE_DO_TABLE",
            "REPLICATE_IGNORE_DB",
            "REPLICATE_IGNORE_TABLE",
            "REPLICATE_REWRITE_DB",
            "REPLICATE_WILD_DO_TABLE",
            "REPLICATE_WILD_IGNORE_TABLE",
            "ROW_COUNT",
            "ROW_FORMAT",
            "ROW_NUMBER",
            "SCHEMA",
            "SCHEMAS",
            "SECOND_MICROSECOND",
            "SELECT",
            "SENSITIVE",
            "SEPARATOR",
            "SET",
            "SHOW",
            "SHUTDOWN",
            "SQLEXCEPTION",
            "SQLSTATE",
            "SQLWARNING",
            "SQL_AFTER_GTIDS",
            "SQL_AFTER_MTS_GAPS",
            "SQL_BEFORE_GTIDS",
            "SQL_BIG_RESULT",
            "SQL_BUFFER_RESULT",
            "SQL_CALC_FOUND_ROWS",
            "SQL_NO_CACHE",
            "SQL_SMALL_RESULT",
            "SQL_THREAD",
            "SQL_TSI_DAY",
            "SQL_TSI_HOUR",
            "SQL_TSI_MINUTE",
            "SQL_TSI_MONTH",
            "SQL_TSI_QUARTER",
            "SQL_TSI_SECOND",
            "SQL_TSI_WEEK",
            "SQL_TSI_YEAR",
            "STRAIGHT_JOIN",
            "SYSTEM",
            "TABLE_CHECKSUM",
            "TABLE_NAME",
            "TINYBLOB",
            "TINYINT",
            "TINYTEXT",
            "TRAILING",
            "TRIGGER",
            "UNION",
            "UPDATE",
            "USAGE",
            "USE",
            "USING",
            "VALUES",
            "VARBINARY",
            "VARCHAR",
            "VARCHARACTER",
            "WHEN",
            "WHERE"];
    }
    
    public function start()
    {
        $this->mysqlParser = new \laf\Logs\Mysql;
        $this->mysqlParser->setLogFile("/var/log/mysql/queries.log");
        $timeNow = new \DateTime("now", new \DateTimeZone("Europe/Paris"));
        $timeNow->sub(new \DateInterval("PT1S"));
        
        $this->mysqlParser->setStartDate($timeNow);
        $this->mysqlParser->setDetectionFunction("laf\Detection\SqlInjection::detection");
    }
    
    public function finish()
    {
        //url decode
        $vulnerableParams = $this->detector->getHttprequest()->getVulnerableParamsFromKeywords($this->keywords);
        
        $timeNow = new \DateTime("now", new \DateTimeZone("Europe/Paris"));
        $this->mysqlParser->setFinishDate($timeNow);
        $this->mysqlParser->parseGeneralLogs($this->detector, $vulnerableParams);
    }
    
    public static function countQuotes($string)
    {
        $nbQuotes = 0;
        
        for($i = 0; $i < strlen($string); $i ++) {
            if($string[$i] === "'" && (!$i || ($i && $string[$i - 1] !== '\\'))) {
                $nbQuotes ++;
            }
        }
    
        return $nbQuotes;
    }
    
    public static function detection($detector, $query, $key, $value, $time)
    {           
        $nbQuotesStatementTotal = 0;
        
        // FIRST CASE  
        // select * from users where username = 'toto' and password = '1' OR 1 = 1 ORDER BY username
        // value : 1' OR 1 = 1
        // SECOND CASE
        // select * from users where username = '1\' OR 1 = 1' and password = '1' OR 1 = 1 ORDER BY username
        // value : 1' OR 1 = 1
        // THIRD CASE
        // select * from users where username = '1 OR 1 = 1' and password = 1 OR 1 = 1 ORDER BY username
        // value : 1 OR 1 = 1
        // FOURTH CASE
        // select * from users where username = '1 OR 1 = 1'
        // value : 1 OR 1 = 1
        $statements = explode($value, $query);
        $nbQuotesValue = SqlInjection::countQuotes($value);
            
        // FIRST CASE  
        // statement1 = select * from users where username = 'toto' and password = '
        // statement2 = ORDER BY username
        // SECOND CASE
        // same as first case
        // THIRD CASE
        // statement1 = select * from users where username = '
        // statement2 = ' and password = 
        // statement3 = ORDER BY username
        // FOURTH CASE
        // statement1 = select * from users where username = '
        // statement2 = '
        
        if(count($statements) > 1) {
            $numstatements = 0;
            foreach($statements as $statement) {
                $numstatements ++;
                $nbQuotesStatement = SqlInjection::countQuotes($statement);
                $nbQuotesStatementTotal += $nbQuotesStatement;
                $nbQuotesStatementTotal += $nbQuotesValue;
                    
                // 1) it's data and  the data container is broken
                // 2) it's not data injection is executed
                if(($nbQuotesStatement % 2 === 1 && $nbQuotesValue % 2 === 1)
                    || (($nbQuotesStatement % 2 === 0 || $nbQuotesStatementTotal % 2 === 0) 
                        && $numstatements % 2 === 1)) {
                        
                    $alarm = new \laf\Alarming\Alarm("sqlinjection", "in $query $key $value", 0, $time);
                    $detector->addAlarm($alarm);
                    break;
                }
            }
        }
    }
}

