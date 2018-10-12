<?php

/**
 * RODS connection class
 * @author Sifang Lu <sifang@sdsc.edu>
 * @copyright Copyright &copy; 2007, TBD
 * @package RODSConn
 */
require_once("RC_base.class.php");
require_once("RC_connect.class.php");

function getRodsConn(RODSAccount $account) {
    $connname = "RODSConn" . ucfirst($account->auth_type);
    $conn = new $connname($account);
    debug(5, "Created $connname instance for account ", $account);
    return $conn;
}

class RODSConn {
    use RC_base, RC_connect;
};

/* The default RODSConn class for basic non-ssl irods authtype */
class RODSConnIrods extends RODSConn {
    use RC_connect_Irods;
}

/* The default RODSConn class for basic non-ssl PAM authtype (PAM auth step only is SSL) */
class RODSConnPAM extends RODSConn {
    use RC_connect_PAM;
}
