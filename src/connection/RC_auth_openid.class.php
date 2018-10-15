<?php

require_once("RODSConn.class.php");

define('AUTH_OPENID_SCHEME', 'openid');
define('AUTH_USER_KEY', 'a_user');
define('AUTH_SCHEME_KEY', 'a_scheme');
define('OPENID_SESSION_VALID', "SUCCESS");

/* All openid authentication related methods */
trait RC_auth_openid {
    private function postConnection() {
    }

    private function auth () {
        debug(8, "openid authentication started");

        $user = $this->account->proxy_user;
        $zone = $this->account->zone;

        if (!array_key_exists('openid', $GLOBALS['PRODS_CONFIG']) ||
            !array_key_exists('provider', $GLOBALS['PRODS_CONFIG']['openid'])) {
            throw new RODSException('No openid provider configured');
        }

        $context = array(
            'provider=' . $GLOBALS['PRODS_CONFIG']['openid']['provider'], // from client_start
            AUTH_USER_KEY."=$user", // from client_request
        );

        $pkt = new RP_authPlugReqInp(AUTH_OPENID_SCHEME, implode(';', $context));
        $msg = new RODSMessage('RODS_API_REQ_T', $pkt, $GLOBALS['PRODS_API_NUMS']['AUTH_PLUG_REQ_AN']);
        $resp = $this->sendMessage($msg, "auth plugin request for ".AUTH_OPENID_SCHEME." user $user");

        // END openid_auth_client_start, BEGIN openid_auth_client_request

        // parse the repsonse for port an nonce
        $authplug = $this->splitKV($resp->getBody()->result_);
        $port = $authplug['port'];
        $nonce = $authplug['nonce'];

        debug(5, "Openid auth plug got port $port and nonce $nonce (result ", $resp->getBody()->result_, "; authplug ", $authplug, ")");

        // setup SSL to irods server and port
        //   -> use partial RODSConn class
        $tmpacc = clone $this->account;
        $tmpacc->port = $port;
        debug(10, "Temp account cloned for port $port ", $tmpacc);

        debug(10, "Create new dummy RODSConn");
        $conn = new RODSConn($tmpacc);
        debug(10, "Making connection");
        // TODO: remove CS NEG autodetect from config
        $conn->makeConnection();
        debug(10, "Enabling SSL on connection");
        $conn->enableSSL();

        // write nonce to server to verify that we are the same client that the auth req came from
        debug(10, "Sending nonce $nonce");
        $conn->writeData($nonce, true);

        // read authorization url
        $url = $conn->readData("authorization url");

        // if the auth url is some magic string (e.g. SUCCESS), session is already authorized, no user action needed
        if ($url == OPENID_SESSION_VALID) {
            debug(10, "Current session is valid");
        } else {
            debug(10, "Got SSO url $url");
            if (http_response_code()) {
                // webservice
            } else {
                // CLI
            }
        }

        // wait (i.e. read from server) for username message now
        $username = $conn->readData("username");
        // wait (i.e. read from server) for session message now
        $session = $conn->readData("session message");
        //session is in form sid=abc;act=def
        $sa = $this->splitKV($session);
        $sid = $sa['sid'];
        $act = $sa['act'];

        // TODO: in libopenid the $session is assigned to _comm->clientUser.authInfo.authStr
        debug(5, "Openid session got username $username act $act and sid $sid (session txt $session; split ", $sa, ")");

        // disconnect (force w/o message)
        $conn->disconnect(true, false);

        // base64_encode the bin authResponseInp_PI
        $response = base64_encode(AUTH_SCHEME_KEY . "=" . AUTH_OPENID_SCHEME);
        $resp_packet = new RP_authResponseInp($response, "$user#$zone");
        $msg = new RODSMessage("RODS_API_REQ_T", $resp_packet, $GLOBALS['PRODS_API_NUMS']['AUTH_RESPONSE_AN']);
        $this->sendMessage($msg, function () {
            $this->disconnect();
            return "Openid login failed for user: $user zone: $zone";
        });
    }

}
