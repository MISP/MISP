<?php
/*
 * distribution.ctp
 *
 * Expected:
 * $data_path => 'Event.distribution'
 * $field['display'] => 'long' or 'short' (optional)
 */

$distribution = Hash::extract($row, $field['data_path']);

if (empty($distribution)) {
    return;
}

$displayMode = $field['display'] ?? 'long';


$map = [
    0 => [
        'label' => __('Your organisation only'),
        'bg'    => '#f8d7da',
        'color' => '#842029',
        'icon'  => 'fa-building'
    ],
    1 => [
        'label' => __('This community only'),
        'bg'    => '#ffe5b4',
        'color' => '#b45309',
        'icon'  => 'fa-users'
    ],
    2 => [
        'label' => __('Connected communities'),
        'bg'    => '#e7d3c3',
        'color' => '#5a3e2b',
        'icon'  => 'fa-network-wired'
    ],
    3 => [
        'label' => __('All communities'),
        'bg'    => '#d1f7e0',
        'color' => '#0f5132',
        'icon'  => 'fa-globe'
    ],
    4 => [
        'label' => __('Sharing group'),
        'bg'    => '#6a96ee',
        'color' => '#0e146d',
        'icon'  => 'fa-share-alt'
    ]
];

$distribution = (int)$distribution[0];

if (isset($map[$distribution])) {
    $config = $map[$distribution];
} else {
    $config = array(
        'label' => __('Unknown'),
        'bg'    => '#f1f1f1',
        'color' => '#333',
        'icon'  => 'fa-question'
    );
}

?>

<span class="badge d-inline-flex align-items-center px-2 py-1"
      style="
        background-color: <?= h($config['bg']) ?>;
        color: <?= h($config['color']) ?>;
        border: 1px solid <?= h($config['color']) ?>20;
        font-weight: 500;
        box-shadow: 0 1px 2px rgba(0,0,0,0.05);
      ">

    <?php if ($displayMode === 'long'): ?>
        <i class="fas <?= h($config['icon']) ?> me-1"
           style="color: <?= h($config['color']) ?>"></i>
        <?= h($config['label']) ?>
    <?php else: ?>
        <i class="fas <?= h($config['icon']) ?>"
           style="color: <?= h($config['color']) ?>"></i>
    <?php endif; ?>

</span>