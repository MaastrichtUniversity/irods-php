<?php

/* All query related methods */
trait RC_query {
    /**
     * This function is depreciated, and kept only for lagacy reasons!
     * Makes a general query to RODS server. Think it as an SQL. "select foo from sometab where bar = '3'". In this example, foo is specified by "$select", bar and "= '3'" are speficed by condition.
     * @param array $select the fields (names) to be returned/interested. There can not be more than 50 input fields. For example:"COL_COLL_NAME" means collection-name.
     * @param array $condition  Array of RODSQueryCondition. All fields are defined in RodsGenQueryNum.inc.php
     * @param array $condition_kw  Array of RODSQueryCondition. All fields are defined in RodsGenQueryKeyWd.inc.php
     * @param integer $startingInx result start from which row.
     * @param integer $maxresult up to how man rows should the result contain.
     * @param boolean $getallrows whether to retreive all results
     * @param boolean $select_attr attributes (array of int) of each select value. For instance, the attribute can be ORDER_BY (0x400) or ORDER_BY_DESC (0x800) to have the results sorted on the server. The default value is 1 for each attribute. Pass empty array or leave the option if you don't want anything fancy.
     * @param integer $continueInx This index can be used to retrieve rest of results, when there is a overflow of the rows (> 500)
     * @return an associated array, keys are the returning field names, each value is an array of the field values. Also, it returns false (boolean), if no rows are found.
     * Note: This function is very low level. It's not recommended for beginners.
     */
    public function genQuery(array $select, array $condition = array(), array $condition_kw = array(), $startingInx = 0, $maxresults = 500, $getallrows = true, array $select_attr = array(), &$continueInx = 0, &$total_num_rows = -1) {
        if (count($select) > 50) {
            trigger_error("genQuery(): Only upto 50 input are supported, rest ignored", E_USER_WARNING);
            $select = array_slice($select, 0, 50);
        }

        $GenQueInp_options = 0;
        if ($total_num_rows != -1) {
            $GenQueInp_options = 1;
        }

        require_once(dirname(__FILE__) . "/../RodsGenQueryNum.inc.php"); //load magic numbers
        require_once(dirname(__FILE__) . "/../RodsGenQueryKeyWd.inc.php"); //load magic numbers
        // contruct select packet (RP_InxIvalPair $selectInp)
        $select_pk = NULL;
        if (count($select) > 0) {
            if (empty($select_attr))
                $select_attr = array_fill(0, count($select), 1);
            $idx = array();
            foreach ($select as $selval) {
                if (isset($GLOBALS['PRODS_GENQUE_NUMS']["$selval"]))
                    $idx[] = $GLOBALS['PRODS_GENQUE_NUMS']["$selval"];
                else
                    trigger_error("genQuery(): select val '$selval' is not support, ignored", E_USER_WARNING);
            }

            $select_pk = new RP_InxIvalPair(count($select), $idx, $select_attr);
        } else {
            $select_pk = new RP_InxIvalPair();
        }

        foreach ($condition_kw as &$cond_kw) {
            if (isset($GLOBALS['PRODS_GENQUE_KEYWD'][$cond_kw->name]))
                $cond_kw->name = $GLOBALS['PRODS_GENQUE_KEYWD'][$cond_kw->name];
        }

        foreach ($condition as &$cond) {
            if (isset($GLOBALS['PRODS_GENQUE_NUMS'][$cond->name]))
                $cond->name = $GLOBALS['PRODS_GENQUE_NUMS'][$cond->name];
        }

        $condInput = new RP_KeyValPair();
        $condInput->fromRODSQueryConditionArray($condition_kw);

        $sqlCondInp = new RP_InxValPair();
        $sqlCondInp->fromRODSQueryConditionArray($condition);

        // construct RP_GenQueryInp packet
        $genque_input_pk = new RP_GenQueryInp($maxresults, $continueInx, $condInput, $select_pk, $sqlCondInp, $GenQueInp_options, $startingInx);

        // contruce a new API request message, with type GEN_QUERY_AN
        $msg = new RODSMessage("RODS_API_REQ_T", $genque_input_pk, $GLOBALS['PRODS_API_NUMS']['GEN_QUERY_AN']);
        fwrite($this->conn, $msg->pack()); // send it
        // get value back
        $msg_resv = new RODSMessage();
        $intInfo = $msg_resv->unpack($this->conn);
        if ($intInfo < 0) {
            if (RODSException::rodsErrCodeToAbbr($intInfo) == 'CAT_NO_ROWS_FOUND') {
                return false;
            }

            throw new RODSException("RODSConn::genQuery has got an error from the server", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
        }
        $genque_result_pk = $msg_resv->getBody();

        $result_arr = array();
        for ($i = 0; $i < $genque_result_pk->attriCnt; $i++) {
            $sql_res_pk = $genque_result_pk->SqlResult_PI[$i];
            $attri_name = $GLOBALS['PRODS_GENQUE_NUMS_REV'][$sql_res_pk->attriInx];
            $result_arr["$attri_name"] = $sql_res_pk->value;
        }
        if ($total_num_rows != -1)
            $total_num_rows = $genque_result_pk->totalRowCount;


        $more_results = true;
        // if there are more results to be fetched
        while (($genque_result_pk->continueInx > 0) && ($more_results === true) && ($getallrows === true)) {
            $msg->getBody()->continueInx = $genque_result_pk->continueInx;
            fwrite($this->conn, $msg->pack()); // re-send it with new continueInx
            // get value back
            $msg_resv = new RODSMessage();
            $intInfo = $msg_resv->unpack($this->conn);
            if ($intInfo < 0) {
                if (RODSException::rodsErrCodeToAbbr($intInfo) == 'CAT_NO_ROWS_FOUND') {
                    $more_results = false;
                    break;
                } else
                    throw new RODSException("RODSConn::genQuery has got an error from the server", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
            }
            $genque_result_pk = $msg_resv->getBody();

            for ($i = 0; $i < $genque_result_pk->attriCnt; $i++) {
                $sql_res_pk = $genque_result_pk->SqlResult_PI[$i];
                $attri_name = $GLOBALS['PRODS_GENQUE_NUMS_REV'][$sql_res_pk->attriInx];
                $result_arr["$attri_name"] = array_merge($result_arr["$attri_name"], $sql_res_pk->value);
            }
        }

        // Make sure and close the query if there are any results left.
        if ($genque_result_pk->continueInx > 0) {
            $msg->getBody()->continueInx = $genque_result_pk->continueInx;
            $msg->getBody()->maxRows = -1;  // tells the server to close the query
            fwrite($this->conn, $msg->pack());
            $msg_resv = new RODSMessage();
            $intInfo = $msg_resv->unpack($this->conn);
            if ($intInfo < 0) {
                throw new RODSException("RODSConn::genQuery has got an error from the server", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
            }
        }

        return $result_arr;
    }

    /**
     * Makes a general query to RODS server. Think it as an SQL. "select foo from sometab where bar = '3'". In this example, foo is specified by "$select", bar and "= '3'" are speficed by condition.
     * @param RODSGenQueSelFlds $select the fields (names) to be returned/interested. There can not be more than 50 input fields. For example:"COL_COLL_NAME" means collection-name.
     * @param RODSGenQueConds $condition  All fields are defined in RodsGenQueryNum.inc.php and RodsGenQueryKeyWd.inc.php
     * @param integer $start result start from which row.
     * @param integer $limit up to how many rows should the result contain. If -1 is passed, all available rows will be returned
     * @return RODSGenQueResults
     * Note: This function is very low level. It's not recommended for beginners.
     */
    public function query(RODSGenQueSelFlds $select, RODSGenQueConds $condition, $start = 0, $limit = -1) {
        if (($select->getCount() < 1) || ($select->getCount() > 50)) {
            throw new RODSException("Only 1-50 fields are supported", 'PERR_USER_INPUT_ERROR');
        }

        // contruct select packet (RP_InxIvalPair $selectInp), and condition packets
        $select_pk = $select->packetize();
        $cond_pk = $condition->packetize();
        $condkw_pk = $condition->packetizeKW();

        // determin max number of results per query
        if (($limit > 0) && ($limit < 500))
            $max_result_per_query = $limit;
        else
            $max_result_per_query = 500;

        $num_fetched_rows = 0;
        $continueInx = 0;
        $results = new RODSGenQueResults();
        do {
            // construct RP_GenQueryInp packet
            $options = 1 | $GLOBALS['PRODS_GENQUE_NUMS']['RETURN_TOTAL_ROW_COUNT'];
            $genque_input_pk = new RP_GenQueryInp($max_result_per_query, $continueInx, $condkw_pk, $select_pk, $cond_pk, $options, $start);

            // contruce a new API request message, with type GEN_QUERY_AN
            $msg = new RODSMessage("RODS_API_REQ_T", $genque_input_pk, $GLOBALS['PRODS_API_NUMS']['GEN_QUERY_AN']);
            fwrite($this->conn, $msg->pack()); // send it
            // get value back
            $msg_resv = new RODSMessage();
            $intInfo = $msg_resv->unpack($this->conn);
            if ($intInfo < 0) {
                if (RODSException::rodsErrCodeToAbbr($intInfo) == 'CAT_NO_ROWS_FOUND') {
                    break;
                }

                throw new RODSException("RODSConn::query has got an error from the server", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
            }
            $genque_result_pk = $msg_resv->getBody();
            $num_row_added = $results->addResults($genque_result_pk);
            $continueInx = $genque_result_pk->continueInx;
            $start = $start + $results->getNumRow();
        } while (($continueInx > 0) &&
        (($results->getNumRow() < $limit) || ($limit < 0)));


        // Make sure and close the query if there are any results left.
        if ($continueInx > 0) {
            $msg->getBody()->continueInx = $continueInx;
            $msg->getBody()->maxRows = -1;  // tells the server to close the query
            fwrite($this->conn, $msg->pack());
            $msg_resv = new RODSMessage();
            $intInfo = $msg_resv->unpack($this->conn);
            if ($intInfo < 0) {
                throw new RODSException("RODSConn::query has got an error from the server", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
            }
        }

        return $results;
    }

}
