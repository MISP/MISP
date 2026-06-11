<?php

/*
 * Expected:
 * $distribution (int)
 * $full (bool) → Print label or just icon
 */

$distribution = isset($distribution) ? (int)$distribution : null;
$full = $full ?? true;

$map = [
    0 => [
        'label' => __('Your organisation only'),
        'bg'    => '#f8d7da',
        'color' => '#842029',
        'icon'  => 'misp-icon misp-icon-organisation misp-simple'
    ],
    1 => [
        'label' => __('This community only'),
        'bg'    => '#ffe5b4',
        'color' => '#b45309',
        'icon'  => 'fas fa-users'
    ],
    2 => [
        'label' => __('Connected communities'),
        'bg'    => '#e7d3c3',
        'color' => '#5a3e2b',
        'icon'  => 'fas fa-network-wired'
    ],
    3 => [
        'label' => __('All communities'),
        'bg'    => '#d1f7e0',
        'color' => '#0f5132',
        'icon'  => 'fas fa-globe'
    ],
    4 => [
        'label' => __('Sharing group'),
        'bg'    => '#6a96ee',
        'color' => '#0e146d',
        'icon'  => 'misp-icon misp-icon-sharing-group misp-simple'
    ],
    5 => [
        'label' => __('Inherited'),
        'bg'    => '#e6b7df',
        'color' => '#380f33a2',
        'icon'  => 'fas fa-code-fork'
    ]
];

$config = $map[$distribution] ?? [
    'label' => __('Unknown'),
    'bg'    => '#f1f1f1',
    'color' => '#333',
    'icon'  => 'fas fa-question'
];

?>

<span class="badge d-inline-flex align-items-center px-2 py-1"
      style="
        background-color: <?= h($config['bg']) ?>;
        color: <?= h($config['color']) ?>;
        border: 1px solid <?= h($config['color']) ?>20;
        font-weight: 500;
      "
      title="<?= h($config['label']) ?>">

    <i class="<?= h($config['icon']) ?>"></i>

    <?php if ($full): ?>
        <?= h($config['label']) ?>
    <?php endif; ?>

</span>