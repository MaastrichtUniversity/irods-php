<?php

class RP_authPlugReqInp extends RODSPacket
{
    public function __construct($auth_scheme, $context)
    {
        $packlets = array('auth_scheme_' => $auth_scheme, 'context_' => $context);
        parent::__construct("authPlugReqInp_PI", $packlets);
    }
}
