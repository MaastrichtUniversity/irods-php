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

if (!defined("O_RDONLY"))
    define("O_RDONLY", 0);
if (!defined("O_WRONLY"))
    define("O_WRONLY", 1);
if (!defined("O_RDWR"))
    define("O_RDWR", 2);
if (!defined("O_TRUNC"))
    define("O_TRUNC", 512);

class RODSConn {

    use RC_directory, RC_file, RC_meta;

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

    public function createTicket($object, $permission = 'read', $ticket = '') {
        if ($this->connected === false) {
            throw new RODSException("createTicket needs an active connection, but the connection is currently inactive", 'PERR_CONN_NOT_ACTIVE');
        }
        if (empty($ticket)) {
            // create a 16 characters long ticket
            $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
            for ($i = 0; $i < 16; $i++)
                $ticket .= $chars[mt_rand(1, strlen($chars)) - 1];
        }

        $ticket_packet = new RP_ticketAdminInp('create', $ticket, $permission, $object);
        $msg = new RODSMessage('RODS_API_REQ_T', $ticket_packet, 723);
        fwrite($this->conn, $msg->pack());

        // get response
        $msg = new RODSMessage();
        $intInfo = $msg->unpack($this->conn);
        if ($intInfo < 0) {
            throw new RODSException('Cannot create ticket "' . $ticket . '" for object "' . $object . '" with permission "' . $permission . '".', $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
        }

        return $ticket;
    }

    public function deleteTicket($ticket) {
        if ($this->connected === false) {
            throw new RODSException("deleteTicket needs an active connection, but the connection is currently inactive", 'PERR_CONN_NOT_ACTIVE');
        }
        $ticket_packet = new RP_ticketAdminInp('delete', $ticket);
        $msg = new RODSMessage('RODS_API_REQ_T', $ticket_packet, 723);
        fwrite($this->conn, $msg->pack());

        // get response
        $msg = new RODSMessage();
        $intInfo = $msg->unpack($this->conn);
        if ($intInfo < 0) {
            throw new RODSException('Cannot delete ticket "' . $ticket . '".', $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
        }
    }

    /**
     * Get a temp password from the server.
     * @param string $key key obtained from server to generate password. If this key is not specified, this function will ask server for a new key.
     * @return string temp password
     */
    public function getTempPassword($key = NULL) {
        if ($this->connected === false) {
            throw new RODSException("getTempPassword needs an active connection, but the connection is currently inactive", 'PERR_CONN_NOT_ACTIVE');
        }
        if (NULL == $key)
            $key = $this->getKeyForTempPassword();

        $auth_str = str_pad($key . $this->account->pass, 100, "\0");
        $pwmd5 = bin2hex(md5($auth_str, true));

        return $pwmd5;
    }

    /**
     * Get a key for temp password from the server. this key can then be hashed together with real password to generate an temp password.
     * @return string key for temp password
     * @throws \RODSException
     */
    public function getKeyForTempPassword() {
        if ($this->connected === false) {
            throw new RODSException("getKeyForTempPassword needs an active connection, but the connection is currently inactive", 'PERR_CONN_NOT_ACTIVE');
        }
        $msg = new RODSMessage("RODS_API_REQ_T", null, $GLOBALS['PRODS_API_NUMS']['GET_TEMP_PASSWORD_AN']);

        fwrite($this->conn, $msg->pack()); // send it
        $msg = new RODSMessage();
        $intInfo = (int) $msg->unpack($this->conn);
        if ($intInfo < 0) {
            throw new RODSException("RODSConn::getKeyForTempPassword has got an error from the server", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
        }
        return ($msg->getBody()->stringToHashWith);
    }

    /**
     * Return a temporary password for a specific user
     *
     * @param $user
     * @return string key for temp password
     * @throws \RODSException
     */
    public function getTempPasswordForUser($user) {
        if ($this->connected === false) {
            throw new RODSException("getTempPasswordForUser needs an active connection, but the connection is currently inactive", 'PERR_CONN_NOT_ACTIVE');
        }
        $user_pk = new RODSPacket("getTempPasswordForOtherInp_PI", ['targetUser' => $user, 'unused' => null]);
        // API request ID: 724
        $msg = new RODSMessage("RODS_API_REQ_T", $user_pk, $GLOBALS['PRODS_API_NUMS']['GET_TEMP_PASSWORD_FOR_OTHER_AN']);

        // Send it
        fwrite($this->conn, $msg->pack());

        // Response
        $msg = new RODSMessage();
        $intInfo = (int) $msg->unpack($this->conn);
        if ($intInfo < 0) {
          throw new RODSException("RODSConn::getTempPasswordForUser has got an error from the server", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
        }
        $key = $msg->getBody()->stringToHashWith;

        $auth_str = str_pad($key . $this->account->pass, 100, "\0");
        $pwmd5 = bin2hex(md5($auth_str, true));

        return $pwmd5;
    }

    /**
     * Get user information
     * @param string username, if not specified, it will use current username instead
     * @return array with fields: id, name, type, zone, dn, info, comment, ctime, mtime. If user not found return empty array.
     */
    public function getUserInfo($user = NULL) {
        if (!isset($user))
            $user = $this->account->user;

        // set selected value
        $select_val = array("COL_USER_ID", "COL_USER_NAME", "COL_USER_TYPE",
            "COL_USER_ZONE", "COL_USER_DN", "COL_USER_INFO",
            "COL_USER_COMMENT", "COL_USER_CREATE_TIME", "COL_USER_MODIFY_TIME");
        $cond = array(new RODSQueryCondition("COL_USER_NAME", $user));
        $que_result = $this->genQuery($select_val, $cond);

        if (false === $que_result) {
            return array();
        } else {
            $retval = array();
            $retval['id'] = $que_result["COL_USER_ID"][0];
            $retval['name'] = $que_result["COL_USER_NAME"][0];
            $retval['type'] = $que_result["COL_USER_TYPE"][0];
            // $retval['zone']=$que_result["COL_USER_ZONE"][0]; This can cause confusion if
            // username is same as another federated grid - sometimes multiple records are returned.
            // Changed source to force user to provide a zone until another method is suggested.
            if ($this->account->zone == "") {
                $retval['zone'] = $que_result["COL_USER_ZONE"][0];
            } else {
                $retval['zone'] = $this->account->zone;
            }
            $retval['dn'] = $que_result["COL_USER_DN"][0];
            $retval['info'] = $que_result["COL_USER_INFO"][0];
            $retval['comment'] = $que_result["COL_USER_COMMENT"][0];
            $retval['ctime'] = $que_result["COL_USER_CREATE_TIME"][0];
            $retval['mtime'] = $que_result["COL_USER_MODIFY_TIME"][0];

            return $retval;
        }
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

    /**
     * This function is depreciated, and kept only for lagacy reasons!
     * Makes a general query to RODS server. Think it as an SQL. "select foo from sometab where bar = '3'". In this example, foo is specified by "$select", bar and "= '3'" are speficed by condition.
     * @param array $select the fields (names) to be returned/interested. There can not be more than 50 input fields. For example:"COL_COLL_NAME" means collection-name.
     * @param array $condition  Array of RODSQueryCondition. All fields are defined in RodsGenQueryNum.inc.php
     * @param array $condition_kw  Array of RODSQueryCondition. All fields are defined in RodsGenQueryKeyWd.inc.php
     * @param integer $startingInx result start from which row.
     * @param integer $maxresult up to how man rows should the result contain.
     * @param boolean $getallrows whether to retreive all results
     * @param boolean $select_attr attributes (array of int) of each select value. For instance, the attribute can be ORDER_BY (0x400) or ORDER_BY_DESC (0x800) to have the results sorted on the server. The default value is 1 for each attribute. Pass empty array or leave the option if you don't want anything fancy.
     * @param integer $continueInx This index can be used to retrieve rest of results, when there is a overflow of the rows (> 500)
     * @return an associated array, keys are the returning field names, each value is an array of the field values. Also, it returns false (boolean), if no rows are found.
     * Note: This function is very low level. It's not recommended for beginners.
     */
    public function genQuery(array $select, array $condition = array(), array $condition_kw = array(), $startingInx = 0, $maxresults = 500, $getallrows = true, array $select_attr = array(), &$continueInx = 0, &$total_num_rows = -1) {
        if (count($select) > 50) {
            trigger_error("genQuery(): Only upto 50 input are supported, rest ignored", E_USER_WARNING);
            $select = array_slice($select, 0, 50);
        }

        $GenQueInp_options = 0;
        if ($total_num_rows != -1) {
            $GenQueInp_options = 1;
        }

        require_once(dirname(__FILE__) . "/../RodsGenQueryNum.inc.php"); //load magic numbers
        require_once(dirname(__FILE__) . "/../RodsGenQueryKeyWd.inc.php"); //load magic numbers
        // contruct select packet (RP_InxIvalPair $selectInp)
        $select_pk = NULL;
        if (count($select) > 0) {
            if (empty($select_attr))
                $select_attr = array_fill(0, count($select), 1);
            $idx = array();
            foreach ($select as $selval) {
                if (isset($GLOBALS['PRODS_GENQUE_NUMS']["$selval"]))
                    $idx[] = $GLOBALS['PRODS_GENQUE_NUMS']["$selval"];
                else
                    trigger_error("genQuery(): select val '$selval' is not support, ignored", E_USER_WARNING);
            }

            $select_pk = new RP_InxIvalPair(count($select), $idx, $select_attr);
        } else {
            $select_pk = new RP_InxIvalPair();
        }

        foreach ($condition_kw as &$cond_kw) {
            if (isset($GLOBALS['PRODS_GENQUE_KEYWD'][$cond_kw->name]))
                $cond_kw->name = $GLOBALS['PRODS_GENQUE_KEYWD'][$cond_kw->name];
        }

        foreach ($condition as &$cond) {
            if (isset($GLOBALS['PRODS_GENQUE_NUMS'][$cond->name]))
                $cond->name = $GLOBALS['PRODS_GENQUE_NUMS'][$cond->name];
        }

        $condInput = new RP_KeyValPair();
        $condInput->fromRODSQueryConditionArray($condition_kw);

        $sqlCondInp = new RP_InxValPair();
        $sqlCondInp->fromRODSQueryConditionArray($condition);

        // construct RP_GenQueryInp packet
        $genque_input_pk = new RP_GenQueryInp($maxresults, $continueInx, $condInput, $select_pk, $sqlCondInp, $GenQueInp_options, $startingInx);

        // contruce a new API request message, with type GEN_QUERY_AN
        $msg = new RODSMessage("RODS_API_REQ_T", $genque_input_pk, $GLOBALS['PRODS_API_NUMS']['GEN_QUERY_AN']);
        fwrite($this->conn, $msg->pack()); // send it
        // get value back
        $msg_resv = new RODSMessage();
        $intInfo = $msg_resv->unpack($this->conn);
        if ($intInfo < 0) {
            if (RODSException::rodsErrCodeToAbbr($intInfo) == 'CAT_NO_ROWS_FOUND') {
                return false;
            }

            throw new RODSException("RODSConn::genQuery has got an error from the server", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
        }
        $genque_result_pk = $msg_resv->getBody();

        $result_arr = array();
        for ($i = 0; $i < $genque_result_pk->attriCnt; $i++) {
            $sql_res_pk = $genque_result_pk->SqlResult_PI[$i];
            $attri_name = $GLOBALS['PRODS_GENQUE_NUMS_REV'][$sql_res_pk->attriInx];
            $result_arr["$attri_name"] = $sql_res_pk->value;
        }
        if ($total_num_rows != -1)
            $total_num_rows = $genque_result_pk->totalRowCount;


        $more_results = true;
        // if there are more results to be fetched
        while (($genque_result_pk->continueInx > 0) && ($more_results === true) && ($getallrows === true)) {
            $msg->getBody()->continueInx = $genque_result_pk->continueInx;
            fwrite($this->conn, $msg->pack()); // re-send it with new continueInx
            // get value back
            $msg_resv = new RODSMessage();
            $intInfo = $msg_resv->unpack($this->conn);
            if ($intInfo < 0) {
                if (RODSException::rodsErrCodeToAbbr($intInfo) == 'CAT_NO_ROWS_FOUND') {
                    $more_results = false;
                    break;
                } else
                    throw new RODSException("RODSConn::genQuery has got an error from the server", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
            }
            $genque_result_pk = $msg_resv->getBody();

            for ($i = 0; $i < $genque_result_pk->attriCnt; $i++) {
                $sql_res_pk = $genque_result_pk->SqlResult_PI[$i];
                $attri_name = $GLOBALS['PRODS_GENQUE_NUMS_REV'][$sql_res_pk->attriInx];
                $result_arr["$attri_name"] = array_merge($result_arr["$attri_name"], $sql_res_pk->value);
            }
        }

        // Make sure and close the query if there are any results left.
        if ($genque_result_pk->continueInx > 0) {
            $msg->getBody()->continueInx = $genque_result_pk->continueInx;
            $msg->getBody()->maxRows = -1;  // tells the server to close the query
            fwrite($this->conn, $msg->pack());
            $msg_resv = new RODSMessage();
            $intInfo = $msg_resv->unpack($this->conn);
            if ($intInfo < 0) {
                throw new RODSException("RODSConn::genQuery has got an error from the server", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
            }
        }

        return $result_arr;
    }

    /**
     * Makes a general query to RODS server. Think it as an SQL. "select foo from sometab where bar = '3'". In this example, foo is specified by "$select", bar and "= '3'" are speficed by condition.
     * @param RODSGenQueSelFlds $select the fields (names) to be returned/interested. There can not be more than 50 input fields. For example:"COL_COLL_NAME" means collection-name.
     * @param RODSGenQueConds $condition  All fields are defined in RodsGenQueryNum.inc.php and RodsGenQueryKeyWd.inc.php
     * @param integer $start result start from which row.
     * @param integer $limit up to how many rows should the result contain. If -1 is passed, all available rows will be returned
     * @return RODSGenQueResults
     * Note: This function is very low level. It's not recommended for beginners.
     */
    public function query(RODSGenQueSelFlds $select, RODSGenQueConds $condition, $start = 0, $limit = -1) {
        if (($select->getCount() < 1) || ($select->getCount() > 50)) {
            throw new RODSException("Only 1-50 fields are supported", 'PERR_USER_INPUT_ERROR');
        }

        // contruct select packet (RP_InxIvalPair $selectInp), and condition packets
        $select_pk = $select->packetize();
        $cond_pk = $condition->packetize();
        $condkw_pk = $condition->packetizeKW();

        // determin max number of results per query
        if (($limit > 0) && ($limit < 500))
            $max_result_per_query = $limit;
        else
            $max_result_per_query = 500;

        $num_fetched_rows = 0;
        $continueInx = 0;
        $results = new RODSGenQueResults();
        do {
            // construct RP_GenQueryInp packet
            $options = 1 | $GLOBALS['PRODS_GENQUE_NUMS']['RETURN_TOTAL_ROW_COUNT'];
            $genque_input_pk = new RP_GenQueryInp($max_result_per_query, $continueInx, $condkw_pk, $select_pk, $cond_pk, $options, $start);

            // contruce a new API request message, with type GEN_QUERY_AN
            $msg = new RODSMessage("RODS_API_REQ_T", $genque_input_pk, $GLOBALS['PRODS_API_NUMS']['GEN_QUERY_AN']);
            fwrite($this->conn, $msg->pack()); // send it
            // get value back
            $msg_resv = new RODSMessage();
            $intInfo = $msg_resv->unpack($this->conn);
            if ($intInfo < 0) {
                if (RODSException::rodsErrCodeToAbbr($intInfo) == 'CAT_NO_ROWS_FOUND') {
                    break;
                }

                throw new RODSException("RODSConn::query has got an error from the server", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
            }
            $genque_result_pk = $msg_resv->getBody();
            $num_row_added = $results->addResults($genque_result_pk);
            $continueInx = $genque_result_pk->continueInx;
            $start = $start + $results->getNumRow();
        } while (($continueInx > 0) &&
        (($results->getNumRow() < $limit) || ($limit < 0)));


        // Make sure and close the query if there are any results left.
        if ($continueInx > 0) {
            $msg->getBody()->continueInx = $continueInx;
            $msg->getBody()->maxRows = -1;  // tells the server to close the query
            fwrite($this->conn, $msg->pack());
            $msg_resv = new RODSMessage();
            $intInfo = $msg_resv->unpack($this->conn);
            if ($intInfo < 0) {
                throw new RODSException("RODSConn::query has got an error from the server", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
            }
        }

        return $results;
    }

}
