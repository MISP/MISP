<?php

echo $this->element('genericElementsBS5/Forms/deleteConfirmationForm', [
    'title'   => __('Destroy sessions'),
    'model'   => 'User',
    'url'     => $baseurl . '/admin/users/destroy/' . h($userId),
    'message' => __(
        'Do you really want to destroy the session(s) for %s? The session(s) will be destroyed the next time the user interacts with MISP.',
        h($targetLabel)
    ),
]);
