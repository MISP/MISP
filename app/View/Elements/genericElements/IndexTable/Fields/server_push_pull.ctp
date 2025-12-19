<?php
$mode = $field['mode'];
$server = $row['Server'];
$serverId = h($server['id']);

if ($mode == "pull") {
    $enabled = !empty($server[$mode]);
} else {
    $enabled = !empty($server[$mode]) && !empty($row['RuleDescription'][$mode]);
}

$rules = $row['RuleDescription'][$mode] ?? null;

$iconClass = $enabled ? 'fa fa-check' : 'fa fa-times';
$ariaLabel = $enabled ? __('Yes') : __('No');

$hiddenRules = (!$enabled || empty($rules)) ? 'hidden' : '';
$hiddenButton = !$enabled ? 'hidden' : '';
?>

<span class="<?= $iconClass ?>" role="img" aria-label="<?= h($ariaLabel) ?>"></span>

<span class="short <?= $hiddenRules ?>"
      data-toggle="popover"
      title="<?= __('Distribution List') ?>"
      data-content="<?= h($rules) ?>">
    (<?= __('Rules') ?>)
</span>

<span role="button"
      tabindex="0"
      aria-label="<?= __('Test Rules') ?>"
      title="<?= __('Test how many Events can be access with the filter rules enabled') ?>"
      class="btn btn-primary <?= $hiddenButton ?>"
      style="line-height:10px; padding: 4px 4px; text-wrap: nowrap;"
      onclick="testSyncRule('<?= $serverId ?>', '<?= h($mode) ?>');">
    <?= $mode === 'push' ? __('Test Push Rules') : __('Test Pull Rules') ?>
</span>

<span id="sync_rule_<?= h($mode) ?>_test_<?= $serverId ?>"></span>
