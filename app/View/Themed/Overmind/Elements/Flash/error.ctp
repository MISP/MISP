<?php
$body = h($message);
$errorDetail = $this->Session->read('flashErrorMessage');
if ($errorDetail && strpos($body, '$flashErrorMessage') !== false) {
    $link = sprintf('<a href="#" data-content="%s" data-toggle="popover">%s</a>', h($errorDetail), __('here'));
    $body = str_replace('$flashErrorMessage', $link, $body);
}
if (isset($params['url'])) {
    $body .= ' <a href="' . h($params['url']) . '">' . h($params['urlName'] ?? $params['url']) . '</a>';
}
echo $this->element('genericElementsBS5/toast', ['kind' => 'danger', 'bodyHtml' => $body]);
