<?php

/**
 * RODS connection class
 * @author Sifang Lu <sifang@sdsc.edu>
 * @copyright Copyright &copy; 2007, TBD
 * @package RODSConn
 */
require_once("RC_base.class.php");
require_once("RC_connect.class.php");

/* The default RODSConn class for basic non-ssl irods authtype and PAM */
class RODSConn {
    use RC_base, RC_connect;
}
