<?php
$ids = (is_string($id) && isset($id[0]) && $id[0] === '[') ? json_decode($id, true) : null;
if (!is_array($ids)) {
    $ids = ($id === '' || $id === false || $id === null) ? [] : [$id];
}
$ids = array_values(array_filter(array_map('intval', $ids)));
$count = count($ids);

$url = $baseurl . '/users/discardRegistrations';
foreach ($ids as $one) {
    $url .= '/id[]:' . $one;
}

$message = $count > 1
    ? __n(
        'Are you sure you wish to discard the selected registration request?',
        'Are you sure you wish to discard the %d selected registration requests?',
        $count,
        $count
    )
    : __('Are you sure you wish to discard this registration request?');

echo $this->element('genericElementsBS5/Forms/deleteConfirmationForm', [
    'title'   => __('Discard registration'),
    'model'   => 'User',
    'url'     => $url,
    'message' => $message,
]);
