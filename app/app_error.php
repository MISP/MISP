<?php
class AppError extends ErrorHandler {
    
    /**
     * Convenience method to display a 403 page.
     *
     * @param array $params Parameters for controller
     * @access public
     */
    function error403($params) {
        extract($params, EXTR_OVERWRITE);

        if (!isset($url)) {
            $url = $this->controller->here;
        }
        $url = Router::normalize($url);
        $this->controller->header("HTTP/1.0 403 Forbidden");
        $this->controller->set(array(
            'code' => '403',
            'name' => __('Forbidden', true),
            'message' => $message,
            'base' => $this->controller->base
        ));
        $this->_outputMessage('error403');
    }
}    
?>
