<?php

class RP_CS_NEG extends RODSPacket
{
  public function __construct()
  {
    $packlets = array("status" => 1, "result" => "");
    parent::__construct("CS_NEG_PI", $packlets);
  }
}
