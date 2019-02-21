<?php

/* All rule related methods */
trait RC_rule {

    /**
     * Excute a user defined rule
     * @param string $rule_body body of the rule. Read this tutorial for details about rules: http://www.irods.org/index.php/Executing_user_defined_rules/workflow
     * @param array $inp_params associative array defining input parameter for micro services used in this rule. only string and keyval pair are supported at this time. If the array value is a string, then type is string, if the array value is an RODSKeyValPair object, it will be treated a keyval pair
     * @param array $out_params an array of names (strings)
     * @param array $remotesvr if this rule need to run at remote server, this associative array should have the following keys:
     *    - 'host' remote host name or address
     *    - 'port' remote port
     *    - 'zone' remote zone
     *    if any of the value is empty, this option will be ignored.
     * @param RODSKeyValPair $options an RODSKeyValPair specifying additional options, purpose of this is unknown at the developement time. Leave it alone if you are as clueless as me...
     * @return an associative array. Each array key is the lable, and each array value's type will depend on the type of $out_param, at this moment, only string and RODSKeyValPair are supported
     */
    public function execUserRule($rule_body, array $inp_params = array(), array $out_params = array(), array $remotesvr = array(), RODSKeyValPair $options = null) {
        $inp_params_packets = array();
        foreach ($inp_params as $inp_param_key => $inp_param_val) {
            if (is_a($inp_param_val, 'RODSKeyValPair')) {
                $inp_params_packets[] = new RP_MsParam($inp_param_key, $inp_param_val->makePacket());
            } else { // a string
                $inp_params_packets[] = new RP_MsParam($inp_param_key, new RP_STR($inp_param_val));
            }
        }
        $inp_param_arr_packet = new RP_MsParamArray($inp_params_packets);

        $out_params_desc = implode('%', $out_params);

        if ((isset($remotesvr['host'])) && (isset($remotesvr['port'])) &&
                (isset($remotesvr['zone']))
        ) {
            $remotesvr_packet = new RP_RHostAddr($remotesvr['host'], $remotesvr['zone'], $remotesvr['port']);
        } else {
            $remotesvr_packet = new RP_RHostAddr();
        }

        if (!isset($options))
            $options = new RODSKeyValPair();

        $options_packet = $options->makePacket();

        $pkt = new RP_ExecMyRuleInp($rule_body, $remotesvr_packet, $options_packet, $out_params_desc, $inp_param_arr_packet);
        $msg = new RODSMessage("RODS_API_REQ_T", $pkt, $GLOBALS['PRODS_API_NUMS']['EXEC_MY_RULE_AN']);
        fwrite($this->conn, $msg->pack()); // send it
        $resv_msg = new RODSMessage();
        $intInfo = (int) $resv_msg->unpack($this->conn);
        if ($intInfo < 0) {
            throw new RODSException("RODSConn::execUserRule has got an error from the server", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
        }
        $retpk = $resv_msg->getBody();
        $param_array = $retpk->MsParam_PI;
        $ret_arr = array();
        foreach ($param_array as $param) {
            if ($param->type == 'STR_PI') {
                $label = $param->label;
                $ret_arr["$label"] = $param->STR_PI->myStr;
            } else
            if ($param->type == 'INT_PI') {
                $label = $param->label;
                $ret_arr["$label"] = $param->INT_PI->myStr;
            } else
            if ($param->type == 'KeyValPair_PI') {
                $label = $param->label;
                $ret_arr["$label"] = RODSKeyValPair::fromPacket($param->KeyValPair_PI);
            } else
            if ($param->type == 'ExecCmdOut_PI') {
                $label = $param->label;
                $exec_ret_val = $param->ExecCmdOut_PI->buf;
                $ret_arr["$label"] = $exec_ret_val;
            } else {
                throw new RODSException("RODSConn::execUserRule got. " .
                "an unexpected output param with type: '$param->type' \n", "PERR_UNEXPECTED_PACKET_FORMAT");
            }
        }
        return $ret_arr;
    }
}