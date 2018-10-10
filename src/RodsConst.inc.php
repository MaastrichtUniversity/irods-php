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


/*
    Print $msg when $lvl is higher than configured level.
    (A newline is added to the message).

    All other arguments are joined into one big message. If any of
    those args is not a string, var_dump of that value is used.

    E.g. debug(5, "start", $some_instance)
*/
function debug() {
    $lvl = func_get_arg(0);
    if (array_key_exists('log', $GLOBALS['PRODS_CONFIG']) &&
        array_key_exists('level', $GLOBALS['PRODS_CONFIG']['log']) &&
        $GLOBALS['PRODS_CONFIG']['log']['level'] >= $lvl) {
        $msg = '';
        for ($i = 1; $i < func_num_args( ); $i++) {
            $val = func_get_arg($i);
            if (is_string($val)) {
                $msg .= $val;
            } else {
                ob_start();
                var_dump($val);
                $msg .= ob_get_contents();
                ob_end_clean();
            };
        };
        print "[DEBUG] ".rtrim($msg)."\n";
    }
}
