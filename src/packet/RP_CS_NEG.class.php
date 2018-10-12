<?php

class RP_CS_NEG extends RODSPacket
{
  public function __construct($status = 1, $result = '')
  {
    $packlets = array("status" => $status, "result" => $result);
    parent::__construct("CS_NEG_PI", $packlets);
  }
}
