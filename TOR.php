<?php

namespace NoLibForIt\TOR;

/**
  *  env vars & default values
  **/
define('TOR_HOST',       getenv('TOR_HOST')       ?: 'localhost'             );
define('TOR_PORT',       getenv('TOR_PORT')       ?: 9050                    );
define('TOR_CTL_PORT',   getenv('TOR_CTL_PORT')   ?: 9051                    );
define('TOR_CTL_SECRET', getenv('TOR_CTL_SECRET') ?: '/run/secret//torpass'  );

class TOR {

  /**
    * TOR::open
    *   acts exactly as fskockopen
    **/
  public static function open( $host, $port, &$errno = null, &$errbuff = null, $timeout = null ) {

    $socket = fsockopen(TOR_HOST,TOR_PORT,$errno,$errbuff,$timeout);
    if( empty($socket) ) {
      return false;
    }

    fwrite($socket, pack("C3", 0x05, 0x01, 0x00) );
    $status = fread($socket,16);
    if ( $status != pack("C2", 0x05, 0x00) ) {
      error_log("[".__CLASS__."] version and/or authentication method not supported.");
      return false;
    }

    fwrite( $socket, pack("C5", 0x05 , 0x01 , 0x00 , 0x03, strlen($host)) . $host . pack("n", $port) );
    $buffer = fread($socket,32);
    if ( $buffer != pack("C10", 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ) ) {
      error_log("[".__CLASS__."] ".TOR_HOST.":".TOR_PORT." connection failed.");
      return false;
    }

    return $socket;

  }

  /**
    * TOR::newnym
    *   sends a NEWNYM signal to TOR control
    **/
  public static function newnym() {

    $ctlSocket = fsockopen(TOR_HOST,TOR_CTL_PORT);
    if( empty($ctlSocket) ) {
      return false;
    }

    $pass = @file_get_contents(TOR_CTL_SECRET);
    if( $pass ) {
      $pass = trim($pass);
    }

    fwrite($ctlSocket, "AUTHENTICATE \"$pass\"\r\n");
    $status = trim(fgets($ctlSocket));
    if( $status != "250 OK" ) {
      error_log("[".__CLASS__."] ".TOR_HOST.":".TOR_CTL_PORT." authentication failed.");
      return false;
    }

    fwrite($ctlSocket,"signal NEWNYM\r\n");
    $status = trim(fgets($ctlSocket));
    if( $status != "250 OK" ) {
      error_log("[".__CLASS__."] ".TOR_HOST.":".TOR_CTL_PORT." NEWNYM failed.");
      return false;
    }

    fwrite($ctlSocket,"QUIT\r\n");
    fclose($ctlSocket);
    return true;

  }

}
?>
