<?php
    $formatDifferences = [
        __('No html support, typographer & autolinker'),
        __('An additional syntax to reference MISP Elements'),
    ];
    $allowedScopes = ['attribute', 'object', 'eventgraph', 'attackmatrix'];
    $allowedScopesHtml = '<code>' . implode('</code> <code>', $allowedScopes) . '</code>';
?>

<h2><?= __('Markdown format') ?></h2>
<p><?= __('The suported markdown format is similar to %s with some differences:', sprintf('<a href="%s" target="_blank">GFM</a>', 'https://github.github.com/gfm/')) ?></p>
<ul>
    <?php foreach($formatDifferences as $formatDifference): ?>
        <li><?= $formatDifference ?></li>
    <?php endforeach; ?>
</ul>

<h2><?= __('Markdown extended format') ?></h2>
<p><?= __('In order to have a visually pleasant report but more importantly, avoid hardcoding elements value or IDs, MISP elements such as attributes and objects can be referenced with the following special syntax') ?></p>
<h4 style="text-align: center;">
    <code style="font-size: 14px;">@[scope](id)</code>
</h4>
<span><?= __('Where:') ?></span>
<ul>
    <li><b>scope</b>: <?= __('Is the scope to which the ID is related.') ?></li>
    <ul>
        <li><?= __('Can be one of the following: %s', $allowedScopesHtml) ?></li>
    </ul>
    <li><b>id</b>: <?= __('Is the ID of the MISP element.') ?></li>
</ul>
<span><?= __('Examples:') ?></span>
<ul>
    <li><code>@[attribute](42)</code>, <code>@[object](12)</code>, <code>@[eventgraph](12)</code></li>
</ul>

<h4><?= __('Picture from attachment attribute') ?></h4>
<p><?= __('Syntax for pictures is like the syntax for referencing MISP elements but with two differences:') ?></p>
<ul>
    <li><?= __('The addition of the %s character to indicate that the picture should be displayed and not the atttribute', '<code>!</code>') ?></li>
    <li><?= __('The scope is fixed to %s', '<code>attribute</code>') ?></li>
</ul>

<h4 style="text-align: center;">
    <code style="font-size: 14px;">@![attribute](id)</code>
</h4>
<span><?= __('Examples:') ?></span>
<ul>
    <li><code>@![attribute](52)</code></li>
</ul>

<h4><?= __('Event\'s ATT&CK matrix') ?></h4>
<p><?=  __('Syntax for embedding the ATT&CK matrix is similar the syntax for referencing MISP elements:') ?></p>
<ul>
    <li><?= __('The scope is fixed to %s', '<code>attackmatrix</code>') ?></li>
    <li><?= __('Here, the ID is irrelevant as the matrix will be taken from the whole event for which the report is linked to') ?></li>
</ul>
<span><?= __('Examples:') ?></span>
<ul>
    <li><code>@[attackmatrix](1)</code></li>
</ul>