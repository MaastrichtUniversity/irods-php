<?php

/* Some generic operation related methods */
trait RC_operation {
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
}