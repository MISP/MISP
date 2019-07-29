<?php

class LinOTP {
    /**
     * LinOTP client library class
     *
     * Provides an abstraction of the common authentication methods of LinOTP.
     */

    /**
     * @var string base url at which the LinOTP instance can be found
     */
    protected $base_url;

    /**
     * @var int Timeout for HTTP requests in milliseconds
     */
    protected $request_timeout;

    /**
     * @var string Path to the CA certificate to use, or null for default (system) CAs.
     */
    protected $ca_path = null;

    /**
     * @var string|null default authentication realm
     */
    protected $realm = null;

    /**
     * LinOTP constructor.
     * @param $base_url string base URL of LinOTP e.g. https://linotp1.corp.local.example.com/
     * @param $request_timeout int timeout in milliseconds before pending HTTP requests shall be canceled
     * @param $ca_path string|null path to the CA bundle or null for system default.
     */
    public function __construct($base_url, $realm=null, int $request_timeout=30000, $ca_path=null)
    {
        $this->base_url = $this->_normalize_url($base_url);
        $this->realm = $realm;
        $this->request_timeout = $request_timeout;
        $this->ca_path = $ca_path;
    }

    /**
     * Strip trailing slashes (from URLs)
     * @param $url
     * @return bool|stringS
     */
    protected function _normalize_url($url) {
        return rtrim($url, "/");
    }

    /**
     * Validate Check
     * Performa a /validate/check call against the given LinOTP instance.
     * @param user the username (opt. including the realm)
     * @param password the password or OTPPin to validate
     * @param transactionId (optional) transaction this validate check call refers to
     * @return bool|mixed returns true or false if the validation was successful, if more information are required (e.g. an OTP) an array is return that contains details.
     */
    public function validate_check($user, $password, $transactionId = null) {
        CakeLog::debug("Calling /validate/check for ${user}");
        $data = array(
            "user" => $user,
            "pass" => $password,
        );

        if ($transactionId != null) {
            $data['transactionid'] = $transactionId;
        }

        if ($this->realm != null) {
            $data['realm'] = $this->realm;
        }

        $response = $this->_post("/validate/check", $data);

        if ($response === false) {
            CakeLog::error("LinOTP request for user ${user} failed.");
            return false;
        }

        if (gettype($response) !== "object") {
            CakeLog::error("Response from LinOTP is not an JSON dictionary/array. Got an " .gettype($response). ": ".$response);
            return false;
        }

        if (!property_exists($response,"result")) {
            CakeLog::error("Missing 'result' key in LinOTP response.");
            return false;
        }
        $result = $response->result;

        if (!property_exists($result,"status")) {
            CakeLog::error("Missing 'status' key in result envelope from LinOTP.");
            return false;
        }
        $status = $result->status;

        if (!property_exists($result, "value")) {
            CakeLog::error("Missing 'value' key in result envelop from LinOTP.");
            return false;
        }
        $value = $result->value;

        $ret = array(
            "status" => $status,
            "value" => $value,
        );

        if (property_exists($response, 'detail')) {
            $ret['detail'] = $response->detail;
        }

        return $ret;
    }

    /**
     * Perform a POST request to the given path on the configured LinOTP instance.
     * @param $path string path part of the request URL
     * @param $data array the post data
     * @return bool|mixed false if the request failed otherwise the request body or decoded json may be returned.
     */
    protected function _post($path, $data) {
        $ch = curl_init();

        $url = $this->base_url . $path;

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        curl_setopt($ch, CURLOPT_TIMEOUT_MS, $this->request_timeout);
        curl_setopt($ch, CURLOPT_USERAGENT, 'MISP LinOTPAuth');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

        // if there is a ca_path set tell curl about it.
        if ($this->ca_path != null) {
            curl_setopt($ch, CURLOPT_CAPATH, $this->ca_path);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 1);
        }

        CakeLog::debug( "Sending POST request to ${url}");
        $response = curl_exec($ch);
        $curl_errno = curl_errno($ch);

        // if the request failed return false
        if ($curl_errno !== 0) {
            $curl_error = curl_error($ch);
            CakeLog::error("curl error: ${curl_error}");
            return false;
        }

        $content_type = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        $status_code = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        CakeLog::debug("Response status: ${status_code}");

        if ($status_code >= 300 || $status_code < 200) {
            CakeLog::debug("Status Code out of range: ${status_code}");
        }

        // if the response content type hints towards JSON try to deserialize it
        if (strpos($content_type, 'application/json') >= 0) {
            $json_data = json_decode($response);
            return $json_data;
        } else {
            return $response;
        }
    }
}
