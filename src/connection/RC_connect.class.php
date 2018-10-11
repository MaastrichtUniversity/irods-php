<?php

/* All directory related methods */
trait RC_connect {
    public function connect() {
        $host = $this->account->host;
        $port = $this->account->port;
        $user = $this->account->user;
        $proxy_user = $this->account->proxy_user;
        $pass = $this->account->pass;
        $zone = $this->account->zone;
        $auth_type = $this->account->auth_type;

        // if we're going to use PAM, set up the socket context
        // options for SSL connections when we open the connection
        $is_pam = strcasecmp($auth_type, "PAM") == 0;
        if ($is_pam) {
            debug(10, "using ssl: for auth_type $auth_type");
            $ssl_opts = array('ssl' => array());
            if (array_key_exists('ssl', $GLOBALS['PRODS_CONFIG'])) {
                $ssl_conf = $GLOBALS['PRODS_CONFIG']['ssl'];
                debug(10, "using ssl: has ssl config ", $ssl_conf);
                if (array_key_exists('verify_peer', $ssl_conf)) {
                    if (strcasecmp("true", $ssl_conf['verify_peer']) == 0) {
                        $ssl_opts['ssl']['verify_peer'] = true;
                    }
                }
                if (array_key_exists('allow_self_signed', $ssl_conf)) {
                    if (strcasecmp("true", $ssl_conf['allow_self_signed']) == 0) {
                        $ssl_opts['ssl']['allow_self_signed'] = true;
                    }
                }
                if (array_key_exists('cafile', $ssl_conf)) {
                    $ssl_opts['ssl']['cafile'] = $ssl_conf['cafile'];
                }
                if (array_key_exists('capath', $ssl_conf)) {
                    $ssl_opts['ssl']['capath'] = $ssl_conf['capath'];
                }
            }
            $ssl_ctx = stream_context_get_default($ssl_opts);
            $sock_timeout = ini_get("default_socket_timeout");
            $conn = @stream_socket_client("tcp://$host:$port", $errno, $errstr, $sock_timeout, STREAM_CLIENT_CONNECT, $ssl_ctx);
        } else {
            $conn = @fsockopen($host, $port, $errno, $errstr);
        }
        if (!$conn)
            throw new RODSException("Connection to '$host:$port' failed.1: ($errno)$errstr. ", "SYS_SOCK_OPEN_ERR");
        $this->conn = $conn;

        // connect to RODS server
        $msg = RODSMessage::packConnectMsg($user, $proxy_user, $zone);
        fwrite($conn, $msg);

        $msg = new RODSMessage();
        $intInfo = $msg->unpack($conn);
        if ($intInfo < 0) {
            throw new RODSException("Connection to '$host:$port' failed.2. User: $proxy_user Zone: $zone", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
        }

        if ($msg->getHeaderType() == 'RODS_CS_NEG_T') {
            debug(10, "RODSConn got connection negotiation request ", $msg);
            $serverneg = $msg->getBody()->result;
            if ($neg == 'CS_NEG_REQUIRE') {
            };
        };

        // are we doing PAM authentication
        if ($is_pam) {
            debug(10, "using ssl: asking server: for auth_type $auth_type");
            // Ask server to turn on SSL
            $req_packet = new RP_sslStartInp();
            $msg = new RODSMessage("RODS_API_REQ_T", $req_packet, $GLOBALS['PRODS_API_NUMS']['SSL_START_AN']);
            fwrite($conn, $msg->pack());
            $msg = new RODSMessage();
            $intInfo = $msg->unpack($conn);
            if ($intInfo < 0) {
                throw new RODSException("Connection to '$host:$port' failed.ssl1. User: $proxy_user Zone: $zone",
                                        $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
            }
            // Turn on SSL on our side
            // TSM Feb 2016: changed crypto method from TLS_CLIENT to SSLv23_CLIENT  because iRODS4.1 expects at least TLS1.2
            //               in PHP 5.4 the TLS_CLIENT will NOT negotiate TLS 1.2 where SSLv23 does so.
            //               see https://bugs.php.net/bug.php?id=65329

            if (!stream_socket_enable_crypto($conn, true, STREAM_CRYPTO_METHOD_SSLv23_CLIENT)) {
                throw new RODSException("Error turning on SSL on connection to server '$host:$port'.");
            }

            // all good ... do the PAM authentication over the encrypted connection
            // FIXME: '24', the TTL in hours, should be a configuration option.
            $req_packet = new RP_pamAuthRequestInp($proxy_user, $pass, 24);

            $msg = new RODSMessage("RODS_API_REQ_T", $req_packet, $GLOBALS['PRODS_API_NUMS']['PAM_AUTH_REQUEST_AN']);
            fwrite($conn, $msg->pack());
            $msg = new RODSMessage();
            $intInfo = $msg->unpack($conn);
            if ($intInfo < 0) {
                throw new RODSException("PAM auth failed at server '$host:$port' User: $proxy_user Zone: $zone", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
            }

            // Update the account object with the temporary password
            // and set the auth_type to irods for this connection
            $pack = $msg->getBody();
            $pass = $this->account->pass = $pack->irodsPamPassword;

            // Done authentication ... turn ask the server to turn off SSL
            $req_packet = new RP_sslEndInp();
            $msg = new RODSMessage("RODS_API_REQ_T", $req_packet, $GLOBALS['PRODS_API_NUMS']['SSL_END_AN']);
            fwrite($conn, $msg->pack());
            $msg = new RODSMessage();
            $intInfo = $msg->unpack($conn);
            if ($intInfo < 0) {
                throw new RODSException("Connection to '$host:$port' failed.ssl2. User: $proxy_user Zone: $zone", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
            }
            // De-activate SSL on the connection
            stream_socket_enable_crypto($conn, false);

            // CJS: For whatever reason some trash is left over for us
            // to read after the SSL shutdown.
            // We need to read and discard those bytes so they don't
            // get in the way of future API responses.
            //
            // There used to be a while(select() > 0){fread(1)} loop
            // here, but that proved to be unreliable, most likely
            // because sometimes not all trash bytes have yet been
            // received at that point. This caused PAM logins to fail
            // randomly.
            //
            // The following fread() call reads all remaining bytes in
            // the current packet (or so it seems).
            //
            // Testing shows there's always exactly 31 bytes to read.

            fread($conn, 1024);
        }

        // request authentication
        $msg = new RODSMessage("RODS_API_REQ_T", NULL, $GLOBALS['PRODS_API_NUMS']['AUTH_REQUEST_AN']);
        fwrite($conn, $msg->pack());

        // get chalange string
        $msg = new RODSMessage();
        $intInfo = $msg->unpack($conn);
        if ($intInfo < 0) {
            throw new RODSException("Connection to '$host:$port' failed.3. User: $proxy_user Zone: $zone", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
        }
        $pack = $msg->getBody();
        $challenge_b64encoded = $pack->challenge;
        $challenge = base64_decode($challenge_b64encoded);

        // encode chalange with passwd
        $pad_pass = str_pad($pass, MAX_PASSWORD_LEN, "\0");
        $pwmd5 = md5($challenge . $pad_pass, true);
        for ($i = 0; $i < strlen($pwmd5); $i++) { //"escape" the string in RODS way...
            if (ord($pwmd5[$i]) == 0) {
                $pwmd5[$i] = chr(1);
            }
        }
        $response = base64_encode($pwmd5);

        // set response
        $resp_packet = new RP_authResponseInp($response, $proxy_user);
        $msg = new RODSMessage("RODS_API_REQ_T", $resp_packet, $GLOBALS['PRODS_API_NUMS']['AUTH_RESPONSE_AN']);
        fwrite($conn, $msg->pack());

        // check if we are connected
        // get chalange string
        $msg = new RODSMessage();
        $intInfo = $msg->unpack($conn);
        if ($intInfo < 0) {
            $this->disconnect();
            $scrambledPass = preg_replace("|.|","*",$pass);
            throw new RODSException("Connection to '$host:$port' failed.4 (login failed, possible wrong user/passwd). User: $proxy_user Pass: $scrambledPass Zone: $zone", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
        }

        $this->connected = true;
        // use ticket if specified
        if (!empty($this->account->ticket)) {
            $ticket_packet = new RP_ticketAdminInp('session', $this->account->ticket);
            $msg = new RODSMessage('RODS_API_REQ_T', $ticket_packet, 723);
            fwrite($conn, $msg->pack());

            // get response
            $msg = new RODSMessage();
            $intInfo = $msg->unpack($conn);
            if ($intInfo < 0) {
                $this->disconnect();
                throw new RODSException('Cannot set session ticket.', $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
            }
        }
    }

    /**
     * Close the connection (socket)
     */
    public function disconnect($force = false) {
        if (($this->connected === false) && ($force !== true))
            return;

        $msg = new RODSMessage("RODS_DISCONNECT_T");
        fwrite($this->conn, $msg->pack());
        fclose($this->conn);
        $this->connected = false;
    }

}