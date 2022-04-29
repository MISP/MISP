<?php
    $href_url = isset($href_url) ? $href_url : $baseurl . '/events/view/' . h($related['id']);
    if (isset($fromEventId)) {
        $href_url .= sprintf('/%s/%s', 1, $fromEventId);
    }
    $hide = isset($hide) ? $hide : false;
    $correlationCount = isset($relatedEventCorrelationCount[$related['id']]) ? (int)$relatedEventCorrelationCount[$related['id']] : null;
?>
<span class="event-correlation<?= $hide ? ' hidden' : '' ?>" data-count="<?= $correlationCount ?>" data-date="<?= h($related['date']) ?>" data-own-org="<?= $ownOrg ? 1 : 0 ?>">
    <span style="display: inline-block; border: 1px solid #ddd; border-radius: 5px; padding: 3px; background-color: white; line-height: 14px;">
        <table>
            <tr>
                <td rowspan="2" style="border-right: 1px solid #ddd; padding-right: 2px; min-width: 24px; max-width: 24px; overflow: hidden; font-size: xx-small; text-overflow: ellipsis;" title="<?= h($related['Orgc']['name']); ?>">
                    <?= $this->OrgImg->getOrgLogo($related['Orgc'], 24) ?>
                </td>
                <td style="padding-left: 2px; white-space: nowrap; text-overflow: ellipsis; overflow: hidden; max-width: 410px;">
                    <a title="<?= h($related['info']); ?>" href="<?= h($href_url)?>">
                        <?= h($related['info']) ?>
                    </a>
                </td>
            </tr>
            <tr>
                <td style="padding-left: 2px;">
                    <i><?= h($related['date']); ?></i>
                    <?php if (isset($correlationCount)): ?>
                        <b style="margin-left: 5px; float: right; cursor: help;" title="<?= __n('This related event contains %s unique correlation', 'This related event contains %s unique correlations', $correlationCount, $correlationCount); ?>"><?= $correlationCount ?></b>
                    <?php endif; ?>
                </td>
            </tr>
        </table>
    </span>
</span>
