<?php

/* All file related methods */
trait RC_file {
    /**
     * Get children file of input direcotory path string
     * @param string $dir input direcotory path string
     * @return an array of string, each string is the name of a child file.  This fuction return empty array, if there is no child direcotry found.
     */
    public function getChildFile($dir, $startingInx = 0, $maxresults = 500, &$total_num_rows = -1) {
        $cond = array(new RODSQueryCondition("COL_COLL_NAME", $dir));
        $que_result = $this->genQuery(array("COL_DATA_NAME"), $cond, array(), $startingInx, $maxresults, true, array(), 0, $total_num_rows);

        if (false === $que_result) {
            return array();
        } else {
            return array_values($que_result["COL_DATA_NAME"]);
        }
    }

    /**
     * Get children file, with basic stats, of input direcotory path string
     * The stats
     * @param string $dir input direcotory path string
     * @param $orderby An associated array specifying how to sort the result by attributes. Each array key is the attribute, array val is 0 (assendent) or 1 (dessendent). The supported attributes are "name", "size", "owner", "mtime".
     * @return an array of RODSFileStats
     */
    public function getChildFileWithStats($dir, array $orderby = array(), $startingInx = 0, $maxresults = 500, &$total_num_rows = -1) {
        // set selected value
        $select_val = array("COL_DATA_NAME", "COL_D_DATA_ID", "COL_DATA_TYPE_NAME",
            "COL_D_RESC_NAME", "COL_DATA_SIZE", "COL_D_OWNER_NAME",
            "COL_D_CREATE_TIME", "COL_D_MODIFY_TIME");
        $select_attr = array();

        // set order by
        if (!empty($orderby)) {
            $select_attr = array_fill(0, count($select_val), 1);
            foreach ($orderby as $key => $val) {
                if ($key == "name") {
                    if ($val == 0)
                        $select_attr[0] = ORDER_BY;
                    else
                        $select_attr[0] = ORDER_BY_DESC;
                } else
                if ($key == "size") {
                    if ($val == 0)
                        $select_attr[4] = ORDER_BY;
                    else
                        $select_attr[4] = ORDER_BY_DESC;
                } else
                if ($key == "owner") {
                    if ($val == 0)
                        $select_attr[5] = ORDER_BY;
                    else
                        $select_attr[5] = ORDER_BY_DESC;
                } else
                if ($key == "mtime") {
                    if ($val == 0)
                        $select_attr[7] = ORDER_BY;
                    else
                        $select_attr[7] = ORDER_BY_DESC;
                }
            }
        }

        $cond = array(new RODSQueryCondition("COL_COLL_NAME", $dir));
        $continueInx = 0;
        $que_result = $this->genQuery($select_val, $cond, array(), $startingInx, $maxresults, true, $select_attr, $continueInx, $total_num_rows);


        if (false === $que_result) {
            return array();
        } else {
            $ret_val = array();
            for ($i = 0; $i < count($que_result['COL_D_DATA_ID']); $i++) {
                $ret_val[] = new RODSFileStats(
                        $que_result['COL_DATA_NAME'][$i], $que_result['COL_DATA_SIZE'][$i], $que_result['COL_D_OWNER_NAME'][$i], $que_result['COL_D_MODIFY_TIME'][$i], $que_result['COL_D_CREATE_TIME'][$i], $que_result['COL_D_DATA_ID'][$i], $que_result['COL_DATA_TYPE_NAME'][$i], $que_result['COL_D_RESC_NAME'][$i]
                );
            }
            return $ret_val;
        }
    }

    /**
     * Get basic stats, of input file path string
     * @param string $filepath input file path string
     * @return RODSFileStats. If file does not exists, return fales.
     */
    public function getFileStats($filepath) {
        $parent = dirname($filepath);
        $filename = basename($filepath);

        $cond = array(new RODSQueryCondition("COL_COLL_NAME", $parent),
            new RODSQueryCondition("COL_DATA_NAME", $filename));

        $que_result = $this->genQuery(
                array("COL_DATA_NAME", "COL_D_DATA_ID", "COL_DATA_TYPE_NAME",
            "COL_D_RESC_NAME", "COL_DATA_SIZE", "COL_D_OWNER_NAME", "COL_D_OWNER_ZONE",
            "COL_D_CREATE_TIME",
            "COL_D_MODIFY_TIME", "COL_D_COMMENTS"), $cond, array(), 0, 1, false);
        if ($que_result === false)
            return false;

        $stats = new RODSFileStats(
                $que_result['COL_DATA_NAME'][0], $que_result['COL_DATA_SIZE'][0], $que_result['COL_D_OWNER_NAME'][0], $que_result['COL_D_OWNER_ZONE'][0], $que_result['COL_D_MODIFY_TIME'][0], $que_result['COL_D_CREATE_TIME'][0], $que_result['COL_D_DATA_ID'][0], $que_result['COL_DATA_TYPE_NAME'][0], $que_result['COL_D_RESC_NAME'][0], $que_result['COL_D_COMMENTS'][0]);
        return $stats;
    }

    /**
     * Check whether a file exists on iRODS server.
     *
     * @param $filePath
     * @param null $rescName
     * @return bool
     * @throws RODSException
     */
    public function fileExists($filePath, $rescName = NULL) {
        $src_pk = new RP_DataObjInp($filePath, 0, 0, 0, 0, 0, 0);

        $msg = new RODSMessage("RODS_API_REQ_T", $src_pk, $GLOBALS['PRODS_API_NUMS']['OBJ_STAT_AN']);
        fwrite($this->conn, $msg->pack());

        $response = new RODSMessage();
        $intInfo = (int) $response->unpack($this->conn);

        switch($intInfo) {
            case 1:

                if ( !empty($rescName) ) {
                    // We are also checking whether the file exists on a specific resource
                    // This requires a genQuery to check whether the object exists.
                    return $this->objExists($filePath, $rescName);
                }

                return true;
            break;

            // I'm not sure when either of these two cases occurs
            case 0:
            case $GLOBALS['PRODS_ERR_CODES']['USER_FILE_DOES_NOT_EXIST']:
                return false;
            break;

            default:
                throw new RODSException("RODSConn::stat has got an error from the server", $GLOBALS['PRODS_ERR_CODES_REV'][$intInfo]);
        }

    }

    /**
     * Open a file path (string) exists on RODS server.
     *
     * @param string $path file path
     * @param string $mode open mode. Supported modes are:
     *   'r'     Open for reading only; place the file pointer at the beginning of the file.
     *   'r+'    Open for reading and writing; place the file pointer at the beginning of the file.
     *   'w'    Open for writing only; place the file pointer at the beginning of the file and truncate the file to zero length. If the file does not exist, attempt to create it.
     *   'w+'    Open for reading and writing; place the file pointer at the beginning of the file and truncate the file to zero length. If the file does not exist, attempt to create it.
     *   'a'    Open for writing only; place the file pointer at the end of the file. If the file does not exist, attempt to create it.
     *   'a+'    Open for reading and writing; place the file pointer at the end of the file. If the file does not exist, attempt to create it.
     *   'x'    Create and open for writing only; place the file pointer at the beginning of the file. If the file already exists, the fopen() call will fail by returning FALSE and generating an error of level E_WARNING. If the file does not exist, attempt to create it. This is equivalent to specifying O_EXCL|O_CREAT flags for the underlying open(2) system call.
     *   'x+'    Create and open for reading and writing; place the file pointer at the beginning of the file. If the file already exists, the fopen() call will fail by returning FALSE and generating an error of level E_WARNING. If the file does not exist, attempt to create it. This is equivalent to specifying O_EXCL|O_CREAT flags for the underlying open(2) system call.
     * @param int $position updated position
     * @param string $rescname . Note that this parameter is required only if the file does not exists (create mode). If the file already exists, and if file resource is unknown or unique or you-dont-care for that file, leave the field, or pass NULL.
     * @param boolean $assum_file_exists . This parameter specifies whether file exists. If the value is false, this mothod will check with RODS server to make sure. If value is true, the check will NOT be done. Default value is false.
     * @param string $filetype . This parameter only make sense when you want to specify the file type, if file does not exists (create mode). If not specified, it defaults to "generic"
     * @param integer $cmode . This parameter is only used for "createmode". It specifies the file mode on physical storage system (RODS vault), in octal 4 digit format. For instance, 0644 is owner readable/writeable, and nothing else. 0777 is all readable, writable, and excutable. If not specified, and the open flag requirs create mode, it defaults to 0644.
     * @return int level 1 descriptor
     * @throws RODSException
     */
    public function openFileDesc($path, $mode, &$position, $rescname = NULL, $assum_file_exists = false, $filetype = 'generic', $cmode = 0644) {
        $create_if_not_exists = false;
        $error_if_exists = false;
        $seek_to_end_of_file = false;
        $position = 0;

        switch ($mode) {
            case 'r':
                $open_flag = O_RDONLY;
                break;
            case 'r+':
                $open_flag = O_RDWR;
                break;
            case 'w':
                $open_flag = O_WRONLY | O_TRUNC;
                $create_if_not_exists = true;
                break;
            case 'w+':
                $open_flag = O_RDWR | O_TRUNC;
                $create_if_not_exists = true;
                break;
            case 'a':
                $open_flag = O_WRONLY;
                $create_if_not_exists = true;
                $seek_to_end_of_file = true;
                break;
            case 'a+':
                $open_flag = O_RDWR;
                $create_if_not_exists = true;
                $seek_to_end_of_file = true;
                break;
            case 'x':
                $open_flag = O_WRONLY;
                $create_if_not_exists = true;
                $error_if_exists = true;
                break;
            case 'x+':
                $open_flag = O_RDWR;
                $create_if_not_exists = true;
                $error_if_exists = true;
                break;
            default:
                throw new RODSException("RODSConn::openFileDesc() does not recognize input mode:'$mode' ", "PERR_USER_INPUT_ERROR");
        }

        if ($assum_file_exists == true) {
            $file_exists = true;
        } else {
            $file_exists = $this->fileExists($path, $rescname);
        }

        if (($error_if_exists) && ($file_exists === true)) {
            throw new RODSException("RODSConn::openFileDesc() expect file '$path' dose not exists with mode '$mode', but the file does exists", "PERR_USER_INPUT_ERROR");
        }

        if (($create_if_not_exists) && ($file_exists === false)) {

            // Create new file
            if ( !empty($rescname)) {
                $keyValPair_pk = new RP_KeyValPair(2, array("rescName", "dataType"), array($rescname, $filetype));
            } else {
                $keyValPair_pk = new RP_KeyValPair(1, array("dataType"), array($filetype));
            }
            $dataObjInp_pk = new RP_DataObjInp($path, $cmode, $open_flag, 0, -1, 0, 0, $keyValPair_pk);
            $api_num = $GLOBALS['PRODS_API_NUMS']['DATA_OBJ_CREATE_AN'];

        } else {
            // open existing file
            // open the file and get descriptor
            if (isset($rescname)) {
                $keyValPair_pk = new RP_KeyValPair(1, array("rescName"), array($rescname));
                $dataObjInp_pk = new RP_DataObjInp
                        ($path, 0, $open_flag, 0, -1, 0, 0, $keyValPair_pk);
            } else {
                $dataObjInp_pk = new RP_DataObjInp
                        ($path, 0, $open_flag, 0, -1, 0, 0);
            }
            $api_num = $GLOBALS['PRODS_API_NUMS']['DATA_OBJ_OPEN_AN'];
        }

        # Don't try to read a file that does not exist.
        if($file_exists === false && $open_flag == O_RDONLY) {
                throw new RODSException("trying to open a file '$path' " .
                "which does not exists with mode '$mode' ", "PERR_USER_INPUT_ERROR");
        }

        $msg = new RODSMessage("RODS_API_REQ_T", $dataObjInp_pk, $api_num);
        fwrite($this->conn, $msg->pack());

        $response = new RODSMessage();
        $intInfo = (int) $response->unpack($this->conn);
        if ($intInfo < 0) {
            if (RODSException::rodsErrCodeToAbbr($intInfo) == 'CAT_NO_ROWS_FOUND') {
                throw new RODSException("trying to open a file '$path' " .
                "which does not exists with mode '$mode' ", "PERR_USER_INPUT_ERROR");
            }
            throw new RODSException("RODSConn::openFileDesc has got an error from the server", $GLOBALS['PRODS_ERR_CODES_REV'][$intInfo]);
        }

        $l1desc = $intInfo;

        if ($seek_to_end_of_file === true) {
            $position = $this->fileSeek($l1desc, 0, SEEK_END);
        }

        return $l1desc;
    }

    /**
     * unlink the file on server
     * @param string $path path of the file
     * @param string $rescname resource name. Not required if there is no other replica.
     * @param boolean $force flag (true or false) indicating whether force delete or not.
     *
     */
    public function fileUnlink($path, $rescname = NULL, $force = false) {
        $options = array();
        if (isset($rescname)) {
            $options['rescName'] = $rescname;
        }
        if ($force == true) {
            $options['forceFlag'] = "";
        }

        if (!empty($options)) {
            $options_pk = new RP_KeyValPair();
            $options_pk->fromAssocArray($options);
            $dataObjInp_pk = new RP_DataObjInp
                    ($path, 0, 0, 0, -1, 0, 0, $options_pk);
        } else {
            $dataObjInp_pk = new RP_DataObjInp
                    ($path, 0, 0, 0, -1, 0, 0);
        }

        $msg = new RODSMessage("RODS_API_REQ_T", $dataObjInp_pk, $GLOBALS['PRODS_API_NUMS']['DATA_OBJ_UNLINK_AN']);
        fwrite($this->conn, $msg->pack()); // send it
        // get value back
        $msg = new RODSMessage();
        $intInfo = (int) $msg->unpack($this->conn);
        if ($intInfo < 0) {
            if (RODSException::rodsErrCodeToAbbr($intInfo) == 'CAT_NO_ROWS_FOUND') {
                throw new RODSException("trying to unlink a file '$path' " .
                "which does not exists", "PERR_USER_INPUT_ERROR");
            }
            throw new RODSException("RODSConn::fileUnlink has got an error from the server", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
        }
    }

    /**
     * close the input file descriptor on RODS server.
     *
     * @param int $l1desc level 1 file descriptor
     */
    public function closeFileDesc($l1desc) {
        try {

            $openedDataObjInp = new RP_OpenedDataObjInp($l1desc);
            $msg = new RODSMessage("RODS_API_REQ_T", $openedDataObjInp, $GLOBALS['PRODS_API_NUMS']['OPENED_DATA_OBJ_CLOSE_AN']);
            fwrite($this->conn, $msg->pack()); // send it
            // get value back
            $msg = new RODSMessage();
            $intInfo = (int) $msg->unpack($this->conn);
            if ($intInfo < 0) {
                trigger_error("Got an error from server:$intInfo", E_USER_WARNING);
            }
        } catch (RODSException $e) {
            trigger_error("Got an exception:$e", E_USER_WARNING);
        }
    }

    /**
     * reads up to length bytes from the file pointer referenced by handle. Reading stops when up to length bytes have been read, EOF (end of file) is reached
     *
     * @param int $l1desc level 1 file descriptor
     * @param int $length up to how many bytes to read.
     * @return the read string.
     */
    public function fileRead($l1desc, $length) {

        $openedDataObjInp = new RP_OpenedDataObjInp($l1desc, $length);
        $msg = new RODSMessage("RODS_API_REQ_T", $openedDataObjInp, $GLOBALS['PRODS_API_NUMS']['OPENED_DATA_OBJ_READ_AN']);

        fwrite($this->conn, $msg->pack()); // send it
        $msg = new RODSMessage();
        $intInfo = (int) $msg->unpack($this->conn);
        if ($intInfo < 0) {
            throw new RODSException("RODSConn::fileRead has got an error from the server", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
        }
        return $msg->getBinstr();
    }

    /**
     * writes up to length bytes from the file pointer referenced by handle. returns number of bytes writtne.
     *
     * @param int $l1desc level 1 file descriptor
     * @param string $string contents (binary safe) to be written
     * @param int $length up to how many bytes to read.
     * @return the number of bytes written.
     */
    public function fileWrite($l1desc, $string, $length = NULL) {
        if (!isset($length))
            $length = strlen($string);

        //$dataObjWriteInp_pk = new RP_dataObjWriteInp($l1desc, $length);

        $openedDataObjInp = new RP_OpenedDataObjInp($l1desc, $length);
        $msg = new RODSMessage("RODS_API_REQ_T", $openedDataObjInp, $GLOBALS['PRODS_API_NUMS']['OPENED_DATA_OBJ_WRITE_AN'], $string);

        fwrite($this->conn, $msg->pack()); // send header and body msg
        fwrite($this->conn, $string); // send contents
        $msg = new RODSMessage();
        $intInfo = (int) $msg->unpack($this->conn);
        if ($intInfo < 0) {
            throw new RODSException("RODSConn::fileWrite has got an error from the server", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
        }
        return $intInfo;
    }

    /**
     *  Sets the file position indicator for the file referenced by l1desc (int descriptor). The new position, measured in bytes from the beginning of the file, is obtained by adding offset to the position specified by whence, whose values are defined as follows:
     *  SEEK_SET - Set position equal to offset bytes.
     *  SEEK_CUR - Set position to current location plus offset.
     *  SEEK_END - Set position to end-of-file plus offset. (To move to a position before the end-of-file, you need to pass a negative value in offset.)
     *  If whence is not specified, it is assumed to be SEEK_SET.
     * @return int the current offset
     */
    public function fileSeek($l1desc, $offset, $whence = SEEK_SET) {
      //  $dataObjReadInp_pk = new RP_fileLseekInp($l1desc, $offset, $whence);
       // $msg = new RODSMessage("RODS_API_REQ_T", $dataObjReadInp_pk, $GLOBALS['PRODS_API_NUMS']['DATA_OBJ_LSEEK_AN']);


        $openedDataObjInp = new RP_OpenedDataObjInp($l1desc, 0, $offset, $whence);
        $msg = new RODSMessage("RODS_API_REQ_T", $openedDataObjInp, $GLOBALS['PRODS_API_NUMS']['OPENED_DATA_OBJ_SEEK_AN']);

        fwrite($this->conn, $msg->pack()); // send it
        $msg = new RODSMessage();
        $intInfo = (int) $msg->unpack($this->conn);
        if ($intInfo < 0) {
            throw new RODSException("RODSConn::fileSeek has got an error from the server", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
        }
        $retpk = $msg->getBody();
        return $retpk->offset;
    }

}