<?php

require_once(dirname(__FILE__) . "/../RodsAPINum.inc.php");
require_once(dirname(__FILE__) . "/../RodsErrorTable.inc.php");
require_once(dirname(__FILE__) . "/../RodsConst.inc.php");

require_once("RC_directory.class.php");
require_once("RC_file.class.php");
require_once("RC_meta.class.php");
require_once("RC_user.class.php");
require_once("RC_query.class.php");
require_once("RC_rule.class.php");
require_once("RC_operation.class.php");

if (!defined("O_RDONLY"))
    define("O_RDONLY", 0);
if (!defined("O_WRONLY"))
    define("O_WRONLY", 1);
if (!defined("O_RDWR"))
    define("O_RDWR", 2);
if (!defined("O_TRUNC"))
    define("O_TRUNC", 512);

/* Almost complete RODSCOnn class except for connect */
trait RC_base {

    use RC_directory, RC_file, RC_meta, RC_user, RC_query, RC_rule, RC_operation;

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

    // this is a temp work around for status packet reply.
    // in status packet protocol, the server gives a status update packet:
    // SYS_SVR_TO_CLI_COLL_STAT (99999996)
    // and it expects an  integer only SYS_CLI_TO_SVR_COLL_STAT_REPLY (99999997)
    private function replyStatusPacket() {
        fwrite($this->conn, pack("N", 99999997));
    }
}
