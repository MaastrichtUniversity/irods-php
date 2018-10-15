<?php

/**
 * RODS connection class
 * @author Sifang Lu <sifang@sdsc.edu>
 * @copyright Copyright &copy; 2007, TBD
 * @package RODSConn
 */
require_once("RC_base.class.php");
require_once("RC_connect.class.php");
require_once("RC_auth_openid.class.php");

function getRodsConn(RODSAccount $account) {
    $connname = "RODSConn" . ucfirst($account->auth_type);
    $conn = new $connname($account);
    debug(5, "Created $connname instance for account ", $account);
    return $conn;
}

class RODSConn {
    //use RC_base, RC_connect; // stupid php5.6 and traits vs subclasses
};

// WARNING: code below copies the traits from parent class,
//   because php5 doesn't allow access to private function across traits
//   Should be fixed in php7

/* The default RODSConn class for basic non-ssl irods authtype */
class RODSConnNative extends RODSConn {
    use RC_auth_Native, RC_base, RC_connect;
}

/* The default RODSConn class for basic non-ssl PAM authtype (PAM auth step only is SSL) */
class RODSConnPAM extends RODSConn {
    use RC_auth_PAM, RC_base, RC_connect;
}

/* The default RODSConn class for basic non-ssl PAM authtype (PAM auth step only is SSL) */
class RODSConnOpenid extends RODSConn {
    use RC_auth_Openid, RC_base, RC_connect;
}
