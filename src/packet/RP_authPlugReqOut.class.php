<?php

class RP_authPlugReqOut extends RODSPacket
{
    public function __construct($result = '')
    {
        $packlets = array('result_' => $result);
        parent::__construct("authPlugReqOut_PI", $packlets);
    }
}
