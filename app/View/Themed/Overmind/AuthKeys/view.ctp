<?php
$key = $data['AuthKey'] ?? [];

$this->set('headerIdentity', $key);
$this->set('headerTitle', __('Auth key #%s', $key['id'] ?? ''));
$this->set('headerTitleHtml', sprintf(
    '<span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 align-self-center rounded-3 shadow-sm me-3 bg-warning-subtle text-warning-emphasis"'
    . ' style="width:1.4em;height:1.4em;"><i class="fas fa-key" style="font-size:.6em;"></i></span>'
    . '<span class="d-flex flex-column justify-content-center min-w-0"><span class="font-monospace">%s<span class="text-body-secondary">%s</span>%s</span>%s</span>',
    h($key['authkey_start'] ?? ''),
    str_repeat('&bull;', 8),
    h($key['authkey_end'] ?? ''),
    trim((string)($key['comment'] ?? '')) === '' ? '' : sprintf(
        '<span class="fw-normal text-body-secondary mt-1" style="font-size:.4em;" title="%s"><i class="fas fa-comment me-1 opacity-50"></i>%s</span>',
        h(__('Comment')),
        h($key['comment'])
    )
));
$this->set('headerTimestamps', $key);

echo $this->element('genericElementsBS5/Layout/view_layout', [
    'data' => $data,
    'tabs' => [
        [
            'id' => 'general',
            'title' => __('General'),
            'icon' => 'fas fa-key',
            'left' => [
                'AuthKeys/View/authkeys_general',
            ],
            'right' => array_merge([
                'AuthKeys/View/authkeys_actions',
            ], $this->RailCard->rail($railCards ?? [], [
                'authkey-lifecycle', 'authkey-activity', 'authkey-addresses',
            ], 'general')),
        ],
    ],
]);
