<?php

/* All user (incl password and ticket) related methods */
trait RC_user {
    public function createTicket($object, $permission = 'read', $ticket = '') {
        if ($this->connected === false) {
            throw new RODSException("createTicket needs an active connection, but the connection is currently inactive", 'PERR_CONN_NOT_ACTIVE');
        }
        if (empty($ticket)) {
            // create a 16 characters long ticket
            $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
            for ($i = 0; $i < 16; $i++)
                $ticket .= $chars[mt_rand(1, strlen($chars)) - 1];
        }

        $ticket_packet = new RP_ticketAdminInp('create', $ticket, $permission, $object);
        $msg = new RODSMessage('RODS_API_REQ_T', $ticket_packet, 723);
        fwrite($this->conn, $msg->pack());

        // get response
        $msg = new RODSMessage();
        $intInfo = $msg->unpack($this->conn);
        if ($intInfo < 0) {
            throw new RODSException('Cannot create ticket "' . $ticket . '" for object "' . $object . '" with permission "' . $permission . '".', $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
        }

        return $ticket;
    }

    public function deleteTicket($ticket) {
        if ($this->connected === false) {
            throw new RODSException("deleteTicket needs an active connection, but the connection is currently inactive", 'PERR_CONN_NOT_ACTIVE');
        }
        $ticket_packet = new RP_ticketAdminInp('delete', $ticket);
        $msg = new RODSMessage('RODS_API_REQ_T', $ticket_packet, 723);
        fwrite($this->conn, $msg->pack());

        // get response
        $msg = new RODSMessage();
        $intInfo = $msg->unpack($this->conn);
        if ($intInfo < 0) {
            throw new RODSException('Cannot delete ticket "' . $ticket . '".', $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
        }
    }

    /**
     * Get a temp password from the server.
     * @param string $key key obtained from server to generate password. If this key is not specified, this function will ask server for a new key.
     * @return string temp password
     */
    public function getTempPassword($key = NULL) {
        if ($this->connected === false) {
            throw new RODSException("getTempPassword needs an active connection, but the connection is currently inactive", 'PERR_CONN_NOT_ACTIVE');
        }
        if (NULL == $key)
            $key = $this->getKeyForTempPassword();

        $auth_str = str_pad($key . $this->account->pass, 100, "\0");
        $pwmd5 = bin2hex(md5($auth_str, true));

        return $pwmd5;
    }

    /**
     * Get a key for temp password from the server. this key can then be hashed together with real password to generate an temp password.
     * @return string key for temp password
     * @throws \RODSException
     */
    public function getKeyForTempPassword() {
        if ($this->connected === false) {
            throw new RODSException("getKeyForTempPassword needs an active connection, but the connection is currently inactive", 'PERR_CONN_NOT_ACTIVE');
        }
        $msg = new RODSMessage("RODS_API_REQ_T", null, $GLOBALS['PRODS_API_NUMS']['GET_TEMP_PASSWORD_AN']);

        fwrite($this->conn, $msg->pack()); // send it
        $msg = new RODSMessage();
        $intInfo = (int) $msg->unpack($this->conn);
        if ($intInfo < 0) {
            throw new RODSException("RODSConn::getKeyForTempPassword has got an error from the server", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
        }
        return ($msg->getBody()->stringToHashWith);
    }

    /**
     * Return a temporary password for a specific user
     *
     * @param $user
     * @return string key for temp password
     * @throws \RODSException
     */
    public function getTempPasswordForUser($user) {
        if ($this->connected === false) {
            throw new RODSException("getTempPasswordForUser needs an active connection, but the connection is currently inactive", 'PERR_CONN_NOT_ACTIVE');
        }
        $user_pk = new RODSPacket("getTempPasswordForOtherInp_PI", ['targetUser' => $user, 'unused' => null]);
        // API request ID: 724
        $msg = new RODSMessage("RODS_API_REQ_T", $user_pk, $GLOBALS['PRODS_API_NUMS']['GET_TEMP_PASSWORD_FOR_OTHER_AN']);

        // Send it
        fwrite($this->conn, $msg->pack());

        // Response
        $msg = new RODSMessage();
        $intInfo = (int) $msg->unpack($this->conn);
        if ($intInfo < 0) {
          throw new RODSException("RODSConn::getTempPasswordForUser has got an error from the server", $GLOBALS['PRODS_ERR_CODES_REV']["$intInfo"]);
        }
        $key = $msg->getBody()->stringToHashWith;

        $auth_str = str_pad($key . $this->account->pass, 100, "\0");
        $pwmd5 = bin2hex(md5($auth_str, true));

        return $pwmd5;
    }

    /**
     * Get user information
     * @param string username, if not specified, it will use current username instead
     * @return array with fields: id, name, type, zone, dn, info, comment, ctime, mtime. If user not found return empty array.
     */
    public function getUserInfo($user = NULL) {
        if (!isset($user))
            $user = $this->account->user;

        // set selected value
        $select_val = array("COL_USER_ID", "COL_USER_NAME", "COL_USER_TYPE",
            "COL_USER_ZONE", "COL_USER_DN", "COL_USER_INFO",
            "COL_USER_COMMENT", "COL_USER_CREATE_TIME", "COL_USER_MODIFY_TIME");
        $cond = array(new RODSQueryCondition("COL_USER_NAME", $user));
        $que_result = $this->genQuery($select_val, $cond);

        if (false === $que_result) {
            return array();
        } else {
            $retval = array();
            $retval['id'] = $que_result["COL_USER_ID"][0];
            $retval['name'] = $que_result["COL_USER_NAME"][0];
            $retval['type'] = $que_result["COL_USER_TYPE"][0];
            // $retval['zone']=$que_result["COL_USER_ZONE"][0]; This can cause confusion if
            // username is same as another federated grid - sometimes multiple records are returned.
            // Changed source to force user to provide a zone until another method is suggested.
            if ($this->account->zone == "") {
                $retval['zone'] = $que_result["COL_USER_ZONE"][0];
            } else {
                $retval['zone'] = $this->account->zone;
            }
            $retval['dn'] = $que_result["COL_USER_DN"][0];
            $retval['info'] = $que_result["COL_USER_INFO"][0];
            $retval['comment'] = $que_result["COL_USER_COMMENT"][0];
            $retval['ctime'] = $que_result["COL_USER_CREATE_TIME"][0];
            $retval['mtime'] = $que_result["COL_USER_MODIFY_TIME"][0];

            return $retval;
        }
    }

}
