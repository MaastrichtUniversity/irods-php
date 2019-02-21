<?php

// following is general defines. Do not modify unless you know what you
// are doing!
define ("ORDER_BY", 0x400);
define ("ORDER_BY_DESC", 0x800);

define("RODS_REL_VERSION", 'rods4.2.3');
define("RODS_API_VERSION", 'd');

/**#@-*/
$_env_path = null;
$_env_paths = array(
    "/etc/irods/irods_environment.json",
    getenv('HOME') ."/.irods/irods_environment.json",
    __DIR__ . "/irods_environment.json"
    );
foreach ($_env_paths as &$_p) {
    if (file_exists($_p)) {
        $_env_path = $_p;
        break;
    };
};

if (!is_null($_env_path)) {
    $data = json_decode(file_get_contents($_env_path));
    /* walk through the data
        - strip any 'irods_' prefix
        - split on 1st _
        - build tree with depth based on size of split

        e.g.
            irods_something  => $GLOBALS['PRODS_CONFIG']['something']
            irods_other_thing  => $GLOBALS['PRODS_CONFIG']['other']['thing']
            irods_yet_another_thing  => $GLOBALS['PRODS_CONFIG']['yet']['another_thing']
    */
    $prefix = 'irods_';
    $lprefix = strlen($prefix);
    foreach ($data as $name => $value) {
        if (substr($name, 0, $lprefix) == $prefix) {
            $name = substr($name, $lprefix);
        }
        $keys = explode("_", $name, 2);
        if (array_key_exists(1, $keys)) {
            $GLOBALS['PRODS_CONFIG'][$keys[0]][$keys[1]] = $value;
        } else {
            $GLOBALS['PRODS_CONFIG'][$keys[0]] = $value;
        };
    }

    debug(1, "Loaded config from environment file $_p. New globals config ", $GLOBALS['PRODS_CONFIG']);
} elseif (file_exists(__DIR__ . "/prods.ini")) {
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
    if (array_key_exists('log', $GLOBALS['PRODS_CONFIG']) &&
        array_key_exists('level', $GLOBALS['PRODS_CONFIG']['log'])) {
        $lvl = func_get_arg(0);
        if ($GLOBALS['PRODS_CONFIG']['log']['level'] >= $lvl) {
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

            if (function_exists('log_message')) {
                // CodeIgniter / yoda
                log_message('debug', $msg);
            } else {
                print "[DEBUG] ".rtrim($msg)."\n";
            }
        }
    };
}
