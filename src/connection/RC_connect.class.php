<?php

define('RODS_CS_NEG', "RODS_CS_NEG");
define('CS_NEG_USE_SSL_KW', "cs_neg_ssl_kw");

define('CS_NEG_FAILURE', "CS_NEG_FAILURE");
define('CS_NEG_USE_SSL', "CS_NEG_USE_SSL");
define('CS_NEG_USE_TCP', "CS_NEG_USE_TCP");

define('CS_NEG_REQUIRE', "CS_NEG_REQUIRE");
define('CS_NEG_REFUSE', "CS_NEG_REFUSE");
define('CS_NEG_DONT_CARE', "CS_NEG_DONT_CARE");

define('CS_NEG_SID_KW', "cs_neg_sid_kw");
define('CS_NEG_RESULT_KW', "cs_neg_result_kw");

define('SSL_CIPHER_LIST', "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");

/* see client_server_negotiations_table [client][server] */
$GLOBALS['CS_NEGOTIATIONS_TABLE'] = array(
    CS_NEG_REQUIRE => array(
        CS_NEG_REQUIRE => CS_NEG_USE_SSL,
        CS_NEG_DONT_CARE => CS_NEG_USE_SSL,
        CS_NEG_REFUSE => CS_NEG_FAILURE),
    CS_NEG_DONT_CARE => array(
        CS_NEG_REQUIRE => CS_NEG_USE_SSL,
        CS_NEG_DONT_CARE => CS_NEG_USE_SSL,
        CS_NEG_REFUSE => CS_NEG_USE_TCP),
    CS_NEG_REFUSE => array(
        CS_NEG_REQUIRE => CS_NEG_FAILURE,
        CS_NEG_DONT_CARE => CS_NEG_USE_TCP,
        CS_NEG_REFUSE => CS_NEG_USE_TCP),
);

/* All connection related methods */
trait RC_connect {
    // setup the (TCP) connection to the irods server
    //    sets the conn attribute
    // public: for use in auth_openid
    public function makeConnection() {
        $host = $this->account->host;
        $port = $this->account->port;

        $sock_timeout = ini_get("default_socket_timeout");
        $conn = @stream_socket_client("tcp://$host:$port", $errno, $errstr, $sock_timeout, STREAM_CLIENT_CONNECT);
        debug(2, "connection made for tcp://$host:$port with timeout $sock_timeout");
        if (!$conn)
            throw new RODSException("Connection to '$host:$port' failed.1: ($errno)$errstr. ", "SYS_SOCK_OPEN_ERR");

        $this->conn = $conn;
    }

    // public: for use in auth_openid
    public function writeData ($data, $addlen = false) {
        $datalen = strlen($data);
        debug(13, "sendMessage fwrite start: $datalen");
        if ($addlen) {
            $written = fwrite($this->conn, pack('i', strlen($data)));
        }
        $written = fwrite($this->conn, $data);
        debug(13, "sendMessage fwrite completed: $written");
    }

    // public: for use in auth_openid
    public function readData ($what) {
        debug(10, "Start to read $what from connection");
        $size = stream_get_contents($this->conn, 4); // 4 is size of int
        // unpack returns assoc array
        //   we have no named format, so the key of the value we are looking for is '1'
        //   (yes, the above is correct).
        $sizeu = unpack('i*', $size);
        if (!array_key_exists(1, $sizeu)) {
            throw new RODSException("readData: failed to unpack $size in integer");
        }

        $sizeint = $sizeu[1];

        $data = stream_get_contents($this->conn, $sizeint);
        debug(10, "Finished reading $what from connection: $data (size $sizeint data len ".strlen($data).")");
        return $data;
    }

    /*
        - write packed message to connection
        - listen for new response message
        - if unpacked response is < 0, throw exception with exception txt
          - if exception txt is an anonymous function, the return value of that function is used as exception text
    */
    private function sendMessage (RODSMessage $msg, $exceptiontxt, $response = true, $data = NULL) {
        if (is_null($data)) {
            $data = $msg->pack();
        };

        $this->writeData($data);

        if (!$response) {
            debug(10, "No response expected");
            return;
        }

        // get challenge string
        $resp = new RODSMessage();
        $intInfo = $resp->unpack($this->conn);
        if ($intInfo < 0) {
            if (is_callable($exceptiontxt)) {
                $txt = $exceptiontxt();
            } else {
                $txt = $exceptiontxt;
            }
            $host = $this->account->host;
            $port = $this->account->port;
            throw new RODSException("Connection to '$host:$port' failed: $txt", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
        }
        return $resp;
    }

    private function splitKV ($txt) {
        $res = array();
        foreach (explode(';', $txt) as $kvtxt) {
            $kv = explode('=', $kvtxt, 2);
            $res[$kv[0]] = $kv[1];
        }
        debug(10, "split kv text $txt in ", $res);
        return $res;
    }

    /* Handle client server negotiation.
       Sets the ssl attribute as a result
    */
    private function handleCSNEG (RODSMessage $msg) {
        $conn = $this->conn;
        $host = $this->account->host;
        $port = $this->account->port;
        if ($msg->getHeaderType() == 'RODS_CS_NEG_T') {
            debug(10, "RODSConn got connection negotiation request ", $msg);
            $serverneg = $msg->getBody()->result;
            $clientneg = $GLOBALS['PRODS_CONFIG']['client']['server_policy'];
            $mode = $GLOBALS['CS_NEGOTIATIONS_TABLE'][$clientneg][$serverneg];

            $txt = "SSL mode $mode for client negotiation $clientneg and server negotiation $serverneg";
            debug(8, "Got $txt");

            if ($mode == CS_NEG_FAILURE) {
                throw new RODSException("Cannot negotiate $txt");
            } else {
                $pkt = new RP_CS_NEG(1, CS_NEG_RESULT_KW . "=$mode;");
                $msg = new RODSMessage('RODS_CS_NEG_T', $pkt);
                $this->sendMessage($msg, "client server negotiation for mode $mode");

                if ($mode == CS_NEG_USE_SSL) {
                    $this->enableSSL();

                    if (!array_key_exists('encryption', $GLOBALS['PRODS_CONFIG'])) {
                        throw new RODSException("Negotiated $mode, but no encrytpion configuration in PRODS_CONFIG");
                    }
                    $ec = $GLOBALS['PRODS_CONFIG']['encryption'];

                    if (!array_key_exists('algorithm', $ec)) {
                        throw new RODSException("Negotiated $mode, but no algorithm in encrytpion configuration in PRODS_CONFIG");
                    }
                    $algo = $ec['algorithm'];

                    if (!array_key_exists('key_size', $ec)) {
                        throw new RODSException("Negotiated $mode, but no key_size in encrytpion configuration in PRODS_CONFIG");
                    }
                    $key_size = $ec['key_size'];

                    if (!array_key_exists('num_hash_rounds', $ec)) {
                        throw new RODSException("Negotiated $mode, but no num_hash_size in encrytpion configuration in PRODS_CONFIG");
                    }
                    $nhr = $ec['num_hash_rounds'];

                    if (!array_key_exists('salt_size', $ec)) {
                        throw new RODSException("Negotiated $mode, but no salt_size in encrytpion configuration in PRODS_CONFIG");
                    }
                    $salt_size = $ec['salt_size'];

                    $key = openssl_random_pseudo_bytes($key_size);

                    /* send encryption details */
                    $enc_msg = new RODSMessage();
                    $enc_msg->setHeader($algo, $key_size, $salt_size, $nhr, 0);
                    $this->sendMessage($enc_msg, '', false);

                    /* send the shared secret */
                    $key_msg = new RODSMessage();
                    $key_msg->setHeader($key, $key_size, 0, 0, 0);
                    $data = $key_msg->pack() . $key;
                    $this->writeData($data);

                    $this->ssl = array(
                        'shared_secret' => $key,
                        'key_size' => $key_size,
                        'salt_size' => $salt_size,
                        'num_hash_rounds' => $nhr,
                        'encryption_algorithm' => $algo,
                    );
                }
            };
        };
    }

    // Make initial connection, handles client server negotiation
    private function initConnection() {
        $user = $this->account->user;
        $proxy_user = $this->account->proxy_user;
        $zone = $this->account->zone;

        $relVersion = RODS_REL_VERSION;
        $apiVersion = RODS_API_VERSION;
        $option = NULL;

        if (array_key_exists('client', $GLOBALS['PRODS_CONFIG']) &&
            array_key_exists('server_negotiation', $GLOBALS['PRODS_CONFIG']['client'])) {
            $neg = $GLOBALS['PRODS_CONFIG']['client']['server_negotiation'];
            debug(8, "packConnectMsg added client server negotiation option $neg");
            $option .= $neg;
        }

        $msgbody = new RP_StartupPack($user, $proxy_user, $zone, $relVersion, $apiVersion, $option);
        $conn_msg = new RODSMessage("RODS_CONNECT_T", $msgbody);

        $resp = $this->sendMessage($conn_msg, "Startup for user $user zone $zone (proxy: $proxy_user)");
        $this->handleCSNEG($resp);

        if (!is_null($this->ssl) && !$this->ssl_enabled) {
            $this->enableSSL();
        }
    }

    private function useTicket () {
        $ticket_packet = new RP_ticketAdminInp('session', $this->account->ticket);
        $msg = new RODSMessage('RODS_API_REQ_T', $ticket_packet, 723);
        $this->sendMessage($msg, function () {
            $this->disconnect();
            return "Cannot set session ticket.";
        });
    }

    public function connect() {

        $this->makeConnection();

        $this->initConnection();

        $this->postConnection();

        $this->auth();

        $this->connected = true;

        // use ticket if specified
        if (!empty($this->account->ticket)) {
            $this->useTicket();
        }
    }

    /**
     * Close the connection (socket)
     */
    public function disconnect($force = false, $message = true) {
        if (($this->connected === false) && ($force !== true))
            return;

        // TODO: Is this really needed?
        // TODO: and before or after the disconnect is send?
        if ($this->ssl_enabled) {
            $this->disableSSL();
        }

        if ($message) {
            $msg = new RODSMessage("RODS_DISCONNECT_T");
            $this->sendMessage($msg, "RODS disconnect", false);
        }

        fclose($this->conn);
        $this->connected = false;
    }

    /* Return a SSL context instance */
    private function getSSLContextOptions () {
        /* context parameters from iRODS ssl network plugin */
        $ssl_opts = array('ssl' => array(
            'ciphers' => SSL_CIPHER_LIST,
            'crypto_method' => STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT,
            'single_dh_use' => true,
            'capture_session_meta' => true, // allows context inspection
        ));

        if (array_key_exists('ssl', $GLOBALS['PRODS_CONFIG'])) {
            $ssl_conf = $GLOBALS['PRODS_CONFIG']['ssl'];
            debug(10, "using ssl: has ssl config ", $ssl_conf);

            if (array_key_exists('verify_peer', $ssl_conf)) {
                $ssl_opts['ssl']['verify_peer'] = strcasecmp("true", $ssl_conf['verify_peer']) == 0;
            } elseif (array_key_exists('verify_server', $ssl_conf)) {
                // from json environment
                // none -> SSL_VERIFY_NONE; cert or hostname -> SSL_VERIFY_PEER
                $ssl_opts['ssl']['verify_peer'] = strcasecmp("none", $ssl_conf['verify_server']) != 0;
            }

            if (array_key_exists('allow_self_signed', $ssl_conf)) {
                if (strcasecmp("true", $ssl_conf['allow_self_signed']) == 0) {
                    $ssl_opts['ssl']['allow_self_signed'] = true;
                }
            }

            /* cafile */
            if (array_key_exists('cafile', $ssl_conf)) {
                $ssl_opts['ssl']['cafile'] = $ssl_conf['cafile'];
            } elseif (array_key_exists('ca_certificate_file', $ssl_conf)) {
                // from json environment
                $ssl_opts['ssl']['cafile'] = $ssl_conf['ca_certificate_file'];
            }

            /* capath */
            if (array_key_exists('capath', $ssl_conf)) {
                $ssl_opts['ssl']['capath'] = $ssl_conf['capath'];
            } elseif (array_key_exists('ca_certificate_path', $ssl_conf)) {
                // from json environment
                $ssl_opts['ssl']['capath'] = $ssl_conf['ca_certificate_path'];

            }
        }

        debug(10, "Created SSL context options ", $ssl_opts);
        return $ssl_opts;
    }

    // Set SSLContext on existing connection
    private function setSSLContext () {
        $ssl_opts = $this->getSSLContextOptions();
        if(stream_context_set_option($this->conn, $ssl_opts)) {
            debug(8, "stream SSL context options set");
        } else {
            throw new RODSException('Cannot set stream SSL context options');
        };
    }

    // Activate SSL on the connection
    // public: for use in auth_openid
    public function enableSSL () {
        debug(5, "Enabling SSL");

        $this->setSSLContext();

        /* use SSLv23 to allow to negotiate TLSv1.2 with server */
        if (!stream_socket_enable_crypto($this->conn, true, STREAM_CRYPTO_METHOD_SSLv23_CLIENT)) {
            throw new RODSException("Failed to enable on SSL on connection");
        };

        $opts = stream_context_get_options($this->conn);
        if (array_key_exists('ssl', $opts)) {
            debug(10, "SSL connection stream context options ", $opts['ssl']['session_meta']);
        } else {
            debug(10, "Failed to get SSL connection stream context options. All options ", $opts);
            throw new RODSException("Failed to get SSL connection stream context options: assuming SSL failed");
        }

        $this->ssl_enabled = true;
    }

    // De-activate SSL on the connection
    function disableSSL () {
        debug(5, "Disabling SSL");

        stream_socket_enable_crypto($this->conn, false);

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

        fread($this->conn, 1024);

        $this->ssl_enabled = false;
    }

}

trait RC_auth_password {
    public function auth () {
        $pass = $this->account->pass;
        $proxy_user = $this->account->proxy_user;
        $zone = $this->account->zone;

        // request (temporary) password based authentication
        $msg = new RODSMessage("RODS_API_REQ_T", NULL, $GLOBALS['PRODS_API_NUMS']['AUTH_REQUEST_AN']);
        $resp = $this->sendMessage($msg, "Authentication challenge request");

        $pack = $resp->getBody();
        $challenge_b64encoded = $pack->challenge;
        $challenge = base64_decode($challenge_b64encoded);

        // encode challenge with passwd
        $pad_pass = str_pad($pass, MAX_PASSWORD_LEN, "\0");
        $pwmd5 = md5($challenge . $pad_pass, true);
        for ($i = 0; $i < strlen($pwmd5); $i++) { //"escape" the string in RODS way...
            if (ord($pwmd5[$i]) == 0) {
                $pwmd5[$i] = chr(1);
            }
        }

        // base64_encode the bin authResponseInp_PI
        $response = base64_encode($pwmd5);

        // set response
        $resp_packet = new RP_authResponseInp($response, "$proxy_user#$zone");
        $msg = new RODSMessage("RODS_API_REQ_T", $resp_packet, $GLOBALS['PRODS_API_NUMS']['AUTH_RESPONSE_AN']);
        $this->sendMessage($msg, function () {
            $this->disconnect();
            $scrambledPass = preg_replace("|.|", "*", $pass);
            return "Login failed, possible wrong user/passwd for user: $proxy_user pass: $scrambledPass zone: $zone";
        });
    }
}

trait RC_auth_Native {
    use RC_auth_password;

    private function postConnection() {
    }
}

trait RC_auth_PAM {
    use RC_auth_password;

    private function postConnection() {
        // Ask server to turn on SSL
        $req_packet = new RP_sslStartInp();
        $msg = new RODSMessage("RODS_API_REQ_T", $req_packet, $GLOBALS['PRODS_API_NUMS']['SSL_START_AN']);
        $this->sendMessage($msg, "PAM SSL Start");

        // otherwise this is already enabled
        if (!$this->ssl_enabled) {
            $this->enableSSL();
        }

        // all good ... do the PAM authentication over the encrypted connection
        // FIXME: '24', the TTL in hours, should be a configuration option.
        $proxy_user = $this->account->proxy_user;
        $pass = $this->account->pass;
        $zone = $this->account->zone;

        $req_packet = new RP_pamAuthRequestInp($proxy_user, $pass, 24);
        $msg = new RODSMessage("RODS_API_REQ_T", $req_packet, $GLOBALS['PRODS_API_NUMS']['PAM_AUTH_REQUEST_AN']);
        $resp = $this->sendMessage($msg, "PAM auth failed for user $proxy_user zone $zone");

        // Update the account object with the temporary password
        $pack = $resp->getBody();
        $this->account->pass = $pack->irodsPamPassword;

        // Only when ssl is not required
        if (is_null($this->ssl) && $this->ssl_enabled) {
            // Done authentication, Ask the server to turn off SSL
            $req_packet = new RP_sslEndInp();
            $msg = new RODSMessage("RODS_API_REQ_T", $req_packet, $GLOBALS['PRODS_API_NUMS']['SSL_END_AN']);
            $this->sendMessage($msg, "PAM SSL END");

            $this->disableSSL();
        }
    }
}
