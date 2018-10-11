<?php

/**
 * RODS connection class
 * @author Sifang Lu <sifang@sdsc.edu>
 * @copyright Copyright &copy; 2007, TBD
 * @package RODSConn
 */
require_once(dirname(__FILE__) . "/../RodsAPINum.inc.php");
require_once(dirname(__FILE__) . "/../RodsErrorTable.inc.php");
require_once(dirname(__FILE__) . "/../RodsConst.inc.php");

require_once("RC_directory.class.php");
require_once("RC_file.class.php");
require_once("RC_meta.class.php");
require_once("RC_user.class.php");
require_once("RC_query.class.php");

if (!defined("O_RDONLY"))
    define("O_RDONLY", 0);
if (!defined("O_WRONLY"))
    define("O_WRONLY", 1);
if (!defined("O_RDWR"))
    define("O_RDWR", 2);
if (!defined("O_TRUNC"))
    define("O_TRUNC", 512);

class RODSConn {

    use RC_directory, RC_file, RC_meta, RC_user, RC_query;

    private $conn;     // (resource) socket connection to RODS server
    private $account;  // RODS user account
    private $idle;
    private $id;
    public $connected;

    /**
     * Makes a new connection to RODS server, with supplied user information (name, passwd etc.)
     * @param string $host hostname
     * @param string $port port number
     * @param string $user username
     * @param string $pass passwd
     * @param string $zone zonename
     */
    public function __construct(RODSAccount &$account) {
        $this->account = $account;
        $this->connected = false;
        $this->conn = NULL;
        $this->idle = true;
    }

    public function __destruct() {
        if ($this->connected === true)
            $this->disconnect();
    }

    public function equals(RODSConn $other) {
        return $this->account->equals($other->account);
    }

    public function getSignature() {
        return $this->account->getSignature();
    }

    public function lock() {
        $this->idle = false;
    }

    public function unlock() {
        $this->idle = true;
    }

    public function isIdle() {
        return ($this->idle);
    }

    public function getId() {
        return $this->id;
    }

    public function setId($id) {
        $this->id = $id;
    }

    public function getAccount() {
        return $this->account;
    }

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

    // this is a temp work around for status packet reply.
    // in status packet protocol, the server gives a status update packet:
    // SYS_SVR_TO_CLI_COLL_STAT (99999996)
    // and it expects an  integer only SYS_CLI_TO_SVR_COLL_STAT_REPLY (99999997)
    private function replyStatusPacket() {
        fwrite($this->conn, pack("N", 99999997));
    }


    /**
     * Returns the contents of a special object.
     *
     * Returns both files and collections
     *
     * @param $path
     * @param int $total_num_rows
     * @return RODSGenQueResults
     * @throws RODSException
     */
    public function getSpecialContent($path, & $total_num_rows = -1) {
        $src_pk = new RP_DataObjInp($path, 0, 0, 0, 0, 0, 0);

        $msg = new RODSMessage("RODS_API_REQ_T", $src_pk, $GLOBALS['PRODS_API_NUMS']['QUERY_SPEC_COLL_AN']);
        fwrite($this->conn, $msg->pack());

        $response = new RODSMessage();
        $intInfo = (int) $response->unpack($this->conn);

        if ( $intInfo !== 0 ) {
            throw new RODSException("RODSConn::getSpecialContent has got an error from the server", $GLOBALS['PRODS_ERR_CODES_REV'][$intInfo]);
        }

        $results = new RODSGenQueResults();
        $result_pk = $response->getBody();

        $results->addResults($result_pk);

        return $results;
    }



    /**
     * Check whether an object exists on iRODS server and is registered in iCAT under a specfic resource
     *
     * @param $filepath
     * @param null $rescname
     * @return bool
     * @throws RODSException
     */
    public function objExists($filepath, $rescname = NULL) {
        $parent = dirname($filepath);
        $filename = basename($filepath);

        if (empty($rescname)) {
            $cond = array(new RODSQueryCondition("COL_COLL_NAME", $parent),
                new RODSQueryCondition("COL_DATA_NAME", $filename));
            $que_result = $this->genQuery(array("COL_D_DATA_ID"), $cond);
        } else {
            $cond = array(new RODSQueryCondition("COL_COLL_NAME", $parent),
                new RODSQueryCondition("COL_DATA_NAME", $filename),
                new RODSQueryCondition("COL_D_RESC_NAME", $rescname));
            $que_result = $this->genQuery(array("COL_D_DATA_ID"), $cond);
        }

        if ($que_result === false)
            return false;
        else
            return true;
    }

    /**
     * Replicate file to resources with options.
     * @param string $path_src full path for the source file
     * @param string $desc_resc destination resource
     * @param array $options an assosive array of options:
     *   - 'all'        (boolean): only meaningful if input resource is a resource group. Replicate to all the resources in the resource group.
     *   - 'backupMode' (boolean): if a good copy already exists in this resource, don't make another copy.
     *   - 'admin'      (boolean): admin user uses this option to backup/replicate other users files
     *   - 'replNum'    (integer): the replica to copy, typically not needed
     *   - 'srcResc'    (string): specifies the source resource of the data object to be replicate, only copies stored in this resource will be replicated. Otherwise, one of the copy will be replicated
     * These options are all 'optional', if omitted, the server will try to do it anyway
     * @return number of bytes written if success, in case of faliure, throw an exception
     */
    public function repl($path_src, $desc_resc, array $options = array()) {
        require_once(dirname(__FILE__) . "/../RODSObjIOOpr.inc.php");
        require_once(dirname(__FILE__) . "/../RodsGenQueryKeyWd.inc.php");

        $optype = REPLICATE_OPR;

        $opt_arr = array();
        $opt_arr[$GLOBALS['PRODS_GENQUE_KEYWD']['DEST_RESC_NAME_KW']] = $desc_resc;
        foreach ($options as $option_key => $option_val) {
            switch ($option_key) {
                case 'all':
                    if ($option_val === true)
                        $opt_arr[$GLOBALS['PRODS_GENQUE_KEYWD']['ALL_KW']] = '';
                    break;

                case 'admin':
                    if ($option_val === true)
                        $opt_arr[$GLOBALS['PRODS_GENQUE_KEYWD']['IRODS_ADMIN_KW']] = '';
                    break;

                case 'replNum':
                    $opt_arr[$GLOBALS['PRODS_GENQUE_KEYWD']['REPL_NUM_KW']] = $option_val;
                    break;

                case 'backupMode':
                    if ($option_val === true)
                        $opt_arr[$GLOBALS['PRODS_GENQUE_KEYWD']
                                ['BACKUP_RESC_NAME_KW']] = $desc_resc;
                    break;

                default:
                    throw new RODSException("Option '$option_key'=>'$option_val' is not supported", 'PERR_USER_INPUT_ERROR');
            }
        }

        $keyvalpair = new RP_KeyValPair();
        $keyvalpair->fromAssocArray($opt_arr);

        $inp_pk = new RP_DataObjInp($path_src, 0, 0, 0, 0, 0, $optype, $keyvalpair);

        $msg = new RODSMessage("RODS_API_REQ_T", $inp_pk, $GLOBALS['PRODS_API_NUMS']['DATA_OBJ_REPL_AN']);
        fwrite($this->conn, $msg->pack()); // send it
        $msg = new RODSMessage();
        $intInfo = (int) $msg->unpack($this->conn);
        if ($intInfo < 0) {
            throw new RODSException("RODSConn::repl has got an error from the server", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
        }

        $retpk = $msg->getBody();
        return $retpk->bytesWritten;
    }

    /**
     * Rename path_src to path_dest.
     * @param string $path_src
     * @param string $path_dest
     * @param integer $path_type if 0, then path type is file, if 1, then path type if directory
     * @return true/false
     */
    public function rename($path_src, $path_dest, $path_type) {
        require_once(dirname(__FILE__) . "/../RODSObjIOOpr.inc.php");

        if ($path_type === 0) {
            $path_type_magic_num = RENAME_DATA_OBJ;
        } else {
            $path_type_magic_num = RENAME_COLL;
        }
        $src_pk = new RP_DataObjInp($path_src, 0, 0, 0, 0, 0, $path_type_magic_num);
        $dest_pk = new RP_DataObjInp($path_dest, 0, 0, 0, 0, 0, $path_type_magic_num);
        $inp_pk = new RP_DataObjCopyInp($src_pk, $dest_pk);
        $msg = new RODSMessage("RODS_API_REQ_T", $inp_pk, $GLOBALS['PRODS_API_NUMS']['DATA_OBJ_RENAME_AN']);
        fwrite($this->conn, $msg->pack()); // send it
        $msg = new RODSMessage();
        $intInfo = (int) $msg->unpack($this->conn);
        if ($intInfo < 0) {
            throw new RODSException("RODSConn::rename has got an error from the server", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
        }
    }


    /**
     * Excute a user defined rule
     * @param string $rule_body body of the rule. Read this tutorial for details about rules: http://www.irods.org/index.php/Executing_user_defined_rules/workflow
     * @param array $inp_params associative array defining input parameter for micro services used in this rule. only string and keyval pair are supported at this time. If the array value is a string, then type is string, if the array value is an RODSKeyValPair object, it will be treated a keyval pair
     * @param array $out_params an array of names (strings)
     * @param array $remotesvr if this rule need to run at remote server, this associative array should have the following keys:
     *    - 'host' remote host name or address
     *    - 'port' remote port
     *    - 'zone' remote zone
     *    if any of the value is empty, this option will be ignored.
     * @param RODSKeyValPair $options an RODSKeyValPair specifying additional options, purpose of this is unknown at the developement time. Leave it alone if you are as clueless as me...
     * @return an associative array. Each array key is the lable, and each array value's type will depend on the type of $out_param, at this moment, only string and RODSKeyValPair are supported
     */
    public function execUserRule($rule_body, array $inp_params = array(), array $out_params = array(), array $remotesvr = array(), RODSKeyValPair $options = null) {
        $inp_params_packets = array();
        foreach ($inp_params as $inp_param_key => $inp_param_val) {
            if (is_a($inp_param_val, 'RODSKeyValPair')) {
                $inp_params_packets[] = new RP_MsParam($inp_param_key, $inp_param_val->makePacket());
            } else { // a string
                $inp_params_packets[] = new RP_MsParam($inp_param_key, new RP_STR($inp_param_val));
            }
        }
        $inp_param_arr_packet = new RP_MsParamArray($inp_params_packets);

        $out_params_desc = implode('%', $out_params);

        if ((isset($remotesvr['host'])) && (isset($remotesvr['port'])) &&
                (isset($remotesvr['zone']))
        ) {
            $remotesvr_packet = new RP_RHostAddr($remotesvr['host'], $remotesvr['zone'], $remotesvr['port']);
        } else {
            $remotesvr_packet = new RP_RHostAddr();
        }

        if (!isset($options))
            $options = new RODSKeyValPair();

        $options_packet = $options->makePacket();

        $pkt = new RP_ExecMyRuleInp($rule_body, $remotesvr_packet, $options_packet, $out_params_desc, $inp_param_arr_packet);
        $msg = new RODSMessage("RODS_API_REQ_T", $pkt, $GLOBALS['PRODS_API_NUMS']['EXEC_MY_RULE_AN']);
        fwrite($this->conn, $msg->pack()); // send it
        $resv_msg = new RODSMessage();
        $intInfo = (int) $resv_msg->unpack($this->conn);
        if ($intInfo < 0) {
            throw new RODSException("RODSConn::execUserRule has got an error from the server", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
        }
        $retpk = $resv_msg->getBody();
        $param_array = $retpk->MsParam_PI;
        $ret_arr = array();
        foreach ($param_array as $param) {
            if ($param->type == 'STR_PI') {
                $label = $param->label;
                $ret_arr["$label"] = $param->STR_PI->myStr;
            } else
            if ($param->type == 'INT_PI') {
                $label = $param->label;
                $ret_arr["$label"] = $param->INT_PI->myStr;
            } else
            if ($param->type == 'KeyValPair_PI') {
                $label = $param->label;
                $ret_arr["$label"] = RODSKeyValPair::fromPacket($param->KeyValPair_PI);
            } else
            if ($param->type == 'ExecCmdOut_PI') {
                $label = $param->label;
                $exec_ret_val = $param->ExecCmdOut_PI->buf;
                $ret_arr["$label"] = $exec_ret_val;
            } else {
                throw new RODSException("RODSConn::execUserRule got. " .
                "an unexpected output param with type: '$param->type' \n", "PERR_UNEXPECTED_PACKET_FORMAT");
            }
        }
        return $ret_arr;
    }

}
