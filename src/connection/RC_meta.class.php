<?php

/* All meta(data) related methods */
trait RC_meta {
    /**
     * Get metadata for a file, dir, resource or user
     * @param char $pathtype 'd'=file, 'c'=dir, 'r'=resource, 'u'=user
     * @param string $name name of the target object. in the case of file and dir, use its full path
     * @return RODSMeta $meta meta data for the target.
     */
    public function getMeta($pathtype, $name) {
        switch ($pathtype) {
            case 'd':
                $select = array("COL_META_DATA_ATTR_NAME", "COL_META_DATA_ATTR_VALUE",
                    "COL_META_DATA_ATTR_UNITS", 'COL_META_DATA_ATTR_ID');
                $condition = array(
                    new RODSQueryCondition("COL_COLL_NAME", dirname($name)),
                    new RODSQueryCondition("COL_DATA_NAME", basename($name))
                );
                break;
            case 'c':
                $select = array("COL_META_COLL_ATTR_NAME", "COL_META_COLL_ATTR_VALUE",
                    "COL_META_COLL_ATTR_UNITS", 'COL_META_COLL_ATTR_ID');
                $condition = array(new RODSQueryCondition("COL_COLL_NAME", $name));
                break;
            case 'r':
                $select = array("COL_META_RESC_ATTR_NAME", "COL_META_RESC_ATTR_VALUE",
                    "COL_META_RESC_ATTR_UNITS", 'COL_META_RESC_ATTR_ID');
                $condition = array(new RODSQueryCondition("COL_R_RESC_NAME", $name));
                break;
            case 'u':
                $select = array("COL_META_USER_ATTR_NAME", "COL_META_USER_ATTR_VALUE",
                    "COL_META_USER_ATTR_UNITS", 'COL_META_USER_ATTR_ID');
                $condition = array(new RODSQueryCondition("COL_USER_NAME", $name));
                break;
            default:
                throw new RODSException("RODSConn::getMeta pathtype '$pathtype' is not supported!", 'PERR_USER_INPUT_ERROR');
        }

        $genque_result = $this->genQuery($select, $condition);

        if ($genque_result === false) {
            return array();
        }
        $ret_array = array();
        for ($i = 0; $i < count($genque_result[$select[0]]); $i++) {
            $ret_array[$i] = new RODSMeta(
                    $genque_result[$select[0]][$i], $genque_result[$select[1]][$i], $genque_result[$select[2]][$i], $genque_result[$select[3]][$i]
            );
        }
        return $ret_array;
    }

    /**
     * Add metadata to a file, dir, resource or user
     * @param char $pathtype 'd'=file, 'c'=dir, 'r'=resource, 'u'=user
     * @param string $name name of the target object. in the case of file and dir, use its full path
     * @param RODSMeta $meta meta data to be added.
     */
    public function addMeta($pathtype, $name, RODSMeta $meta) {
        $pkt = new RP_ModAVUMetadataInp("add", "-$pathtype", $name, $meta->name, $meta->value, $meta->units);
        $msg = new RODSMessage("RODS_API_REQ_T", $pkt, $GLOBALS['PRODS_API_NUMS']['MOD_AVU_METADATA_AN']);
        fwrite($this->conn, $msg->pack()); // send it
        $msg = new RODSMessage();
        $intInfo = (int) $msg->unpack($this->conn);
        if ($intInfo < 0) {
            throw new RODSException("RODSConn::addMeta has got an error from the server", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
        }
    }

    /**
     * remove metadata to a file, dir, resource or user
     * @param char $pathtype 'd'=file, 'c'=dir, 'r'=resource, 'u'=user
     * @param string $name name of the target object. in the case of file and dir, use its full path
     * @param RODSMeta $meta meta data to be removed.
     */
    public function rmMeta($pathtype, $name, RODSMeta $meta) {
        $pkt = new RP_ModAVUMetadataInp("rm", "-$pathtype", $name, $meta->name, $meta->value, $meta->units);
        $msg = new RODSMessage("RODS_API_REQ_T", $pkt, $GLOBALS['PRODS_API_NUMS']['MOD_AVU_METADATA_AN']);
        fwrite($this->conn, $msg->pack()); // send it
        $msg = new RODSMessage();
        $intInfo = (int) $msg->unpack($this->conn);
        if ($intInfo < 0) {
            throw new RODSException("RODSConn::rmMeta has got an error from the server", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
        }
    }

    /**
     * remove metadata to a file, dir, resource or user
     * @param char $pathtype 'd'=file, 'c'=dir, 'r'=resource, 'u'=user
     * @param string $name name of the target object. in the case of file and dir, use its full path
     * @param integer $metaid id of the metadata to be removed.
     */
    public function rmMetaByID($pathtype, $name, $metaid) {
        $pkt = new RP_ModAVUMetadataInp("rmi", "-$pathtype", $name, $metaid);
        $msg = new RODSMessage("RODS_API_REQ_T", $pkt, $GLOBALS['PRODS_API_NUMS']['MOD_AVU_METADATA_AN']);
        fwrite($this->conn, $msg->pack()); // send it
        $msg = new RODSMessage();
        $intInfo = (int) $msg->unpack($this->conn);
        if ($intInfo < 0) {
            if (RODSException::rodsErrCodeToAbbr($intInfo) != 'CAT_SUCCESS_BUT_WITH_NO_INFO') {
                throw new RODSException("RODSConn::rmMetaByID has got an error from the server", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
            }
        }
    }

    /**
     * copy metadata between file, dir, resource or user
     * @param char $pathtype_src source path type 'd'=file, 'c'=dir, 'r'=resource, 'u'=user
     * @param char $pathtype_dest destination path type 'd'=file, 'c'=dir, 'r'=resource, 'u'=user
     * @param string $name_src name of the source target object. in the case of file and dir, use its full path
     * @param string $name_dest name of the destination target object. in the case of file and dir, use its full path
     */
    public function cpMeta($pathtype_src, $pathtype_dest, $name_src, $name_dest) {
        $pkt = new RP_ModAVUMetadataInp("cp", "-$pathtype_src", "-$pathtype_dest", $name_src, $name_dest);
        $msg = new RODSMessage("RODS_API_REQ_T", $pkt, $GLOBALS['PRODS_API_NUMS']['MOD_AVU_METADATA_AN']);
        fwrite($this->conn, $msg->pack()); // send it
        $msg = new RODSMessage();
        $intInfo = (int) $msg->unpack($this->conn);
        if ($intInfo < 0) {
            throw new RODSException("RODSConn::cpMeta has got an error from the server", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
        }
    }

}
