<?php

// following is general defines. Do not modify unless you know what you
// are doing!
define ("ORDER_BY", 0x400);
define ("ORDER_BY_DESC", 0x800);

define("RODS_REL_VERSION", 'rods4.2.3');
define("RODS_API_VERSION", 'd');

/**#@-*/

if (file_exists(__DIR__ . "/prods.ini")) {
    $GLOBALS['PRODS_CONFIG'] = parse_ini_file(__DIR__ . "/prods.ini", true);
}
else {
    $GLOBALS['PRODS_CONFIG'] = array();
}