<?php
    $href_url = isset($href_url) ? $href_url : $baseurl . '/events/view/' . intval($related['id']);
    if (isset($fromEventId)) {
        $href_url .= "/1/$fromEventId";
    }
    $hide = isset($hide) ? $hide : false;
    $correlationCount = isset($relatedEventCorrelationCount[$related['id']]) ? (int)$relatedEventCorrelationCount[$related['id']] : null;
?>
<div class="event-correlation<?= $hide ? ' hidden-important' : '' ?>" data-count="<?= $correlationCount ?>" data-date="<?= h($related['date']) ?>" data-own-org="<?= $ownOrg ? 1 : 0 ?>">
    <table>
        <tr>
            <td rowspan="2" class="org" title="<?= h($related['Orgc']['name']); ?>">
                <?= $this->OrgImg->getOrgLogo($related['Orgc'], 24) ?>
            </td>
            <td class="info">
                <a title="<?= h($related['info']); ?>" href="<?= h($href_url)?>">
                    <?= h($related['info']) ?>
                </a>
            </td>
        </tr>
        <tr>
            <td style="padding-left: 2px;">
                <time><?= h($related['date']); ?></time>
                <?php if (isset($correlationCount)): ?>
                    <b onclick="setAttributeFilter('correlationId', <?= intval($related['id']) ?>)" title="<?= __n('This related event contains %s unique correlation. Click to show them.', 'This related event contains %s unique correlations. Click to show them.', $correlationCount, $correlationCount); ?>"><?= $correlationCount ?></b>
                <?php endif; ?>
            </td>
        </tr>
    </table>
</div>
