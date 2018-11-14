<?php

/* All directory related methods */
trait RC_directory {
    /**
     * Make a new directory
     * @param string $dir input direcotory path string
     */
    public function mkdir($dir) {
        $collInp_pk = new RP_CollInp($dir);
        $msg = new RODSMessage("RODS_API_REQ_T", $collInp_pk, $GLOBALS['PRODS_API_NUMS']['COLL_CREATE_AN']);
        fwrite($this->conn, $msg->pack()); // send it
        $msg = new RODSMessage();
        $intInfo = (int) $msg->unpack($this->conn);
        if ($intInfo < 0) {
            if (RODSException::rodsErrCodeToAbbr($intInfo) == 'CATALOG_ALREADY_HAS_ITEM_BY_THAT_NAME') {
                throw new RODSException("Collection '$dir' Already exists!", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
            }
            throw new RODSException("RODSConn::mkdir has got an error from the server", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
        }
    }

    /**
     * remove a directory
     * @param string  $dirpath input direcotory path string
     * @param boolean $recursive whether recursively delete all child files and child directories recursively.
     * @param boolean $force whether force delete the file/dir. If force delete, all files will be wiped physically. Else, they are moved to trash derectory.
     * @param array   $additional_flags An array of keyval pairs (array) reprenting additional flags passed to the server/client message. Each keyval pair is an array with first element repsenting the key, and second element representing the value (default to ''). Supported keys are:
     * -    'irodsRmTrash' - whether this rm is a rmtrash operation
     * -    'irodsAdminRmTrash' - whether this rm is a rmtrash operation done by admin user
     * @param mixed   $status_update_func It can be an string or array that represents the status update function (see http://us.php.net/manual/en/language.pseudo-types.php#language.types.callback), which can update status based on the server status update. Leave it blank or 'null' if there is no need to update the status. The function will be called with an assossive arry as parameter, supported fields are:
     * - 'filesCnt' - finished number of files from previous update (normally 10 but not the last update)
     * - 'lastObjPath' - last object that was processed.
     * If this function returns 1, progress will be stopped.
     */
    public function rmdir($dirpath, $recursive = true, $force = false, $additional_flags = array(), $status_update_func = null) {
        $options = array();
        if ($force === true) {
            $options["forceFlag"] = "";
        }
        if ($recursive === true) {
            $options["recursiveOpr"] = "";
        }
        foreach ($additional_flags as $flagkey => $flagval) {
            if (!empty($flagkey))
                $options[$flagkey] = $flagval;
        }
        $options_pk = new RP_KeyValPair();
        $options_pk->fromAssocArray($options);

        $collInp_pk = new RP_CollInp($dirpath, $options_pk);
        $msg = new RODSMessage("RODS_API_REQ_T", $collInp_pk, $GLOBALS['PRODS_API_NUMS']['RM_COLL_AN']);
        fwrite($this->conn, $msg->pack()); // send it
        $msg = new RODSMessage();
        $intInfo = (int) $msg->unpack($this->conn);
        while ($msg->getBody() instanceof RP_CollOprStat) {
            if (is_callable($status_update_func)) { // call status update function if requested
                $status = call_user_func($status_update_func, array(
                    "filesCnt" => $msg->getBody()->filesCnt,
                    "lastObjPath" => $msg->getBody()->lastObjPath
                        )
                );
                if (false === $status)
                    throw new Exception("status_update_func failed!");
                else if (1 == $status) {
                    return;
                }
            }

            if ($intInfo == 0) //stop here if intinfo =0 (process completed)
                break;
            $this->replyStatusPacket();
            $msg = new RODSMessage();
            $intInfo = (int) $msg->unpack($this->conn);
        }

        if ($intInfo < 0) {
            if (RODSException::rodsErrCodeToAbbr($intInfo) == 'CAT_NO_ROWS_FOUND') {
                return;
            }
            throw new RODSException("RODSConn::rmdir has got an error from the server", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
        }
    }

    /**
     * Get children direcotories of input direcotory path string
     * @param string $dir input direcotory path string
     * @return an array of string, each string is the name of a child directory. This fuction return empty array, if there is no child direcotry found
     */
    public function getChildDir($dir, $startingInx = 0, $maxresults = 500, &$total_num_rows = -1) {
        $cond = array(new RODSQueryCondition("COL_COLL_PARENT_NAME", $dir));
        $que_result = $this->genQuery(array("COL_COLL_NAME"), $cond, array(), $startingInx, $maxresults, true, array(), 0, $total_num_rows);

        if (false === $que_result) {
            return array();
        } else {
            if ($dir == "/") {
                $result = array();
                foreach ($que_result["COL_COLL_NAME"] as $childdir) {
                    if ($childdir != "/") {
                        $result[] = $childdir;
                    }
                }
                return $result;
            }

            return array_values($que_result["COL_COLL_NAME"]);
        }
    }

    /**
     * Get children direcotories, with basic stats,  of input direcotory path string
     * @param string $dir input direcotory path string
     * @param array $orderby An associated array specifying how to sort the result by attributes. Each array key is the attribute, array val is 0 (assendent) or 1 (dessendent). The supported attributes are "name", "owner", "mtime".
     * @param int $startingInx
     * @param int $maxresults
     * @param int $total_num_rows
     * @return RODSDirStats[]
     * @throws RODSException
     */
    public function getChildDirWithStats($dir, $orderby = array(), $startingInx = 0, $maxresults = 500, &$total_num_rows = -1) {
        // set selected value
        $select_val = array("COL_COLL_NAME", "COL_COLL_ID", "COL_COLL_OWNER_NAME",
            "COL_COLL_OWNER_ZONE", "COL_COLL_CREATE_TIME", "COL_COLL_MODIFY_TIME",
            "COL_COLL_COMMENTS", "COL_COLL_TYPE", "COL_COLL_INFO1", "COL_COLL_INFO2");
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
                if ($key == "owner") {
                    if ($val == 0)
                        $select_attr[2] = ORDER_BY;
                    else
                        $select_attr[2] = ORDER_BY_DESC;
                } else
                if ($key == "mtime") {
                    if ($val == 0)
                        $select_attr[5] = ORDER_BY;
                    else
                        $select_attr[5] = ORDER_BY_DESC;
                }
            }
        }

        $cond = array(new RODSQueryCondition("COL_COLL_PARENT_NAME", $dir));
        $continueInx = 0;
        $que_result = $this->genQuery($select_val, $cond, array(), $startingInx, $maxresults, true, $select_attr, $continueInx, $total_num_rows);

        if (false === $que_result) {
            return array();
        } else {
            $ret_val = array();
            for ($i = 0; $i < count($que_result['COL_COLL_ID']); $i++) {
                if ($que_result['COL_COLL_NAME'][$i] != "/") {
                    $ret_val[] = new RODSDirStats(
                        basename($que_result['COL_COLL_NAME'][$i]),
                        $que_result['COL_COLL_OWNER_NAME'][$i],
                        $que_result['COL_COLL_OWNER_ZONE'][$i],
                        $que_result['COL_COLL_MODIFY_TIME'][$i],
                        $que_result['COL_COLL_CREATE_TIME'][$i],
                        $que_result['COL_COLL_ID'][$i],
                        $que_result['COL_COLL_COMMENTS'][$i],
                        $que_result['COL_COLL_TYPE'][$i],
                        $que_result['COL_COLL_INFO1'][$i],
                        $que_result['COL_COLL_INFO2'][$i]
                    );
                }
            }
            return $ret_val;
        }
    }

    /**
     * Get basic stats, of input dir path string
     * @param string $dirpath input dir path string
     * @return RODSDirStats. If dir does not exists, return fales.
     */
    public function getDirStats($dirpath) {
        $cond = array(new RODSQueryCondition("COL_COLL_NAME", $dirpath));

        $que_result = $this->genQuery(
                array("COL_COLL_NAME", "COL_COLL_ID", "COL_COLL_OWNER_NAME",
            "COL_COLL_OWNER_ZONE", "COL_COLL_CREATE_TIME", "COL_COLL_MODIFY_TIME",
            "COL_COLL_COMMENTS"), $cond, array(), 0, 1, false);
        if ($que_result === false)
            return false;

        $stats = new RODSDirStats(
            basename($que_result['COL_COLL_NAME'][0]),
            $que_result['COL_COLL_OWNER_NAME'][0],
            $que_result['COL_COLL_OWNER_ZONE'][0],
            $que_result['COL_COLL_MODIFY_TIME'][0],
            $que_result['COL_COLL_CREATE_TIME'][0],
            $que_result['COL_COLL_ID'][0],
            $que_result['COL_COLL_COMMENTS'][0],
            $que_result['COL_COLL_TYPE'][0],
            $que_result['COL_COLL_INFO1'][0],
            $que_result['COL_COLL_INFO2'][0]
        );
        return $stats;
    }

    /**
     * Check whether a directory (in string) exists on RODS server.
     * @return true/false
     */
    public function dirExists($dir) {
        $cond = array(new RODSQueryCondition("COL_COLL_NAME", $dir));
        $que_result = $this->genQuery(array("COL_COLL_ID"), $cond);

        if ($que_result === false)
            return false;
        else
            return true;
    }


}