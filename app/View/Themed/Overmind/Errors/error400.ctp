<?php
$code = $this->response->statusCode();
// AppController::blackhole() throws 'csrf' for a bad token, the generic
// message for every other Security component failure.
if (in_array($message, ['csrf', 'The request has been black-holed'], true)) {
    echo $this->element('errorPage', [
        'label' => __('CSRF error'),
        'icon' => 'fa-solid fa-shield-halved',
        'title' => __('You have tripped the cross-site request forgery protection of MISP'),
        'message' => __('This happens usually when you try to resubmit the same form with invalidated CSRF tokens or you had a form open too long and the CSRF tokens simply expired. Just go back to the previous page and refresh the form (by reloading the same url) so that the tokens get refreshed.'),
        'error' => $error,
    ]);
    return;
}

$details = [
    404 => __d('cake', 'The requested address %s was not found on this server.', "<strong>'$url'</strong>"),
    405 => __d('cake', 'You don\'t have permission to access %s.', "<strong>'$url'</strong>"),
];
echo $this->element('errorPage', [
    'label' => __('Error %s', $code),
    'icon' => $code === 403 ? 'fa-solid fa-lock' : 'fa-solid fa-triangle-exclamation',
    'title' => $message,
    'message' => $details[$code] ?? '',
    'error' => $error,
]);
