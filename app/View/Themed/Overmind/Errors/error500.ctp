<?= $this->element('errorPage', [
    'label' => __('Error %s', $this->response->statusCode()),
    'icon' => 'fa-solid fa-triangle-exclamation',
    'title' => $message,
    'message' => __d('cake', 'An Internal Error Has Occurred. please try your action again. If the problem persists, contact your administrator. For administrators, refer to the error.log (normally found at MISP/app/tmp/logs/error.log)'),
    'error' => $error,
]);
