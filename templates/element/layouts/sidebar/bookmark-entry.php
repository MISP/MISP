<?php
    use Cake\Routing\Router;
    use Cake\ORM\TableRegistry;

    $this->userSettingsTable = TableRegistry::getTableLocator()->get('UserSettings');

    $seed = 'sb-' . mt_rand();
    $icon = $entry['icon'] ?? '';
    $label = $entry['label'] ?? '';
    $name = $entry['name'] ?? '';
    $active = false;

    $url = $entry['url'];

    $currentURL = Router::url(null);
    if ($url == $currentURL) {
        $active = true;
    }

    $validURI = $this->userSettingsTable->validURI($url);

    echo $this->Bootstrap->button([
        'nodeType' => 'a',
        'text' => h($label),
        'title' => h($name),
        'variant' => 'dark',
        'outline' => !$active,
        'size' => 'sm',
        'icon' => h($icon),
        'class' => ['mb-1', !$validURI ? 'disabled' : ''],
        'params' => [
            'href' => $validURI ? h($url) : '#',
        ]
    ]);
?>
