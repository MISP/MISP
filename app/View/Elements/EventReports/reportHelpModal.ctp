<?php
    $formatDifferences = [
        __('No html support, typographer & autolinker'),
        __('An additional syntax to reference MISP Elements'),
    ];
    $allowedScopes = ['attribute', 'object', 'galaxymatrix' ,'tag'];
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
<p><?= __('In order to have a visually pleasant report but more importantly, avoid hardcoding element\'s value or ID, MISP elements such as attributes and objects can be referenced with the following special syntax') ?></p>
<h4 style="text-align: center;">
    <code style="font-size: 14px;">@[scope](UUID)</code>
</h4>
<span><?= __('Where:') ?></span>
<ul>
    <li><b>scope</b>: <?= __('Is the scope to which the UUID is related to.') ?></li>
    <ul>
        <li><?= __('Can be one of the following: %s', $allowedScopesHtml) ?></li>
    </ul>
    <li><b>UUID</b>: <?= __('Is the UUID of the MISP element with only one exception for the tag') ?></li>
</ul>
<span><?= __('Examples:') ?></span>
<ul>
    <li><code>@[attribute](5f1accda-cde4-47fc-baf1-6ab8f331dc3b)</code></li>
    <li><code>@[object](5f1accda-cde4-47fc-baf1-6ab8f331dc3b)</code></li>
    <li><code>@[galaxymatrix](5f1accda-cde4-47fc-baf1-6ab8f331dc3b)</code></li>
</ul>

<h4><?= __('Pictures from attachment-type attributes') ?></h4>
<p><?= __('Syntax for pictures is like the syntax for referencing MISP elements but with two differences:') ?></p>
<ul>
    <li><?= __('The addition of the %s character to indicate that the picture should be displayed and not the atttribute', '<code>!</code>') ?></li>
    <li><?= __('The scope is fixed to %s as only attributes can contain a file', '<code>attribute</code>') ?></li>
</ul>

<h4 style="text-align: center;">
    <code style="font-size: 14px;">@![attribute](UUID)</code>
</h4>
<span><?= __('Examples:') ?></span>
<ul>
    <li><code>@![attribute](5f1accda-cde4-47fc-baf1-6ab8f331dc3b)</code></li>
</ul>

<h4><?= __('Tags') ?></h4>
<p><?=  __('Syntax for representing tags is similar the syntax for referencing MISP elements but with two differences:') ?></p>
<ul>
    <li><?= __('The scope is fixed to %s', '<code>tag</code>') ?></li>
    <li><?= __('The UUID is replaced by the tag name sa tags don\'t have UUID') ?></li>
</ul>
<span><?= __('Examples:') ?></span>
<ul>
    <li><code>@[tag](tlp:green)</code></li>
    <li><code>@[tag](misp-galaxy:threat-actor="APT 29")</code></li>
</ul>

<h4><?= __('Event\'s Galaxy matrixes') ?></h4>
<p><?=  __('Syntax for embedding the ATT&CK matrix or any other galaxy matrixes is similar to the syntax for referencing MISP elements:') ?></p>
<ul>
    <li><?= __('The scope is fixed to %s', '<code>galaxymatrix</code>') ?></li>
    <li><?= __('The matrix will be generated for the whole event for which the report is linked to') ?></li>
</ul>
<span><?= __('Examples:') ?></span>
<ul>
    <li><code>@[galaxymatrix](5f1accda-cde4-47fc-baf1-6ab8f331dc3b)</code></li>
</ul>