<?php
/**
 * AJAX-loaded object listing for view2.
 *
 * Variables: $objects, $total, $page, $limit, $event
 */
$eventId = $event['Event']['id'];
$totalPages = $limit > 0 ? (int)ceil($total / $limit) : 1;
?>
<div id="objectListContainer">
    <div class="pagination-info" style="margin-bottom:8px;">
        <strong><?= __n(
            '%s object', '%s objects',
            $total, $total
        ) ?></strong>
        <?php if ($totalPages > 1): ?>
            &mdash; <?= __('Page %s of %s',
                $page, $totalPages
            ) ?>
        <?php endif; ?>
    </div>

<?php if (!empty($objects)): ?>
    <?php foreach ($objects as $object): ?>
    <div class="object-card"
         style="border:1px solid #ddd;
                border-radius:4px;
                margin-bottom:10px;
                padding:8px;">
        <div class="object-header"
             style="margin-bottom:6px;">
            <strong>
                <i class="fas fa-cube"></i>
                <?= h($object['name']) ?>
            </strong>
            <span class="muted"
                  style="font-size:0.85em">
                <?= h(
                    $object['meta-category'] ?? ''
                ) ?>
            </span>
            <?php if (!empty($object['comment'])): ?>
                &mdash;
                <em><?= h($object['comment']) ?></em>
            <?php endif; ?>
            <span class="muted pull-right"
                  style="font-size:0.85em">
                <?= date(
                    'Y-m-d',
                    (int)$object['timestamp']
                ) ?>
            </span>
        </div>
        <?php if (
            !empty($object['Attribute'])
        ): ?>
        <table class="table table-striped
                       table-condensed"
               style="margin-bottom:0">
            <thead>
                <tr>
                    <th><?= __('Relation') ?></th>
                    <th><?= __('Type') ?></th>
                    <th><?= __('Value') ?></th>
                    <th><?= __('Correlations') ?></th>
                    <th><?= __('IDS') ?></th>
                </tr>
            </thead>
            <tbody>
            <?php foreach (
                $object['Attribute'] as $attr
            ): ?>
                <tr>
                    <td><?= h(
                        $attr['object_relation'] ?? ''
                    ) ?></td>
                    <td><?= h($attr['type']) ?></td>
                    <td class="break-word">
                        <?= h($attr['value']) ?>
                        <?php if (
                            !empty($attr['warnings'])
                        ): ?>
                            <i class="fas
                                      fa-exclamation-triangle"
                               style="color:orange"
                               title="<?= h(implode(
                                   ', ',
                                   array_column(
                                       $attr['warnings'],
                                       'warninglist_name'
                                   )
                               )) ?>"></i>
                        <?php endif; ?>
                    </td>
                    <td>
                    <?php
                        $relCount = count(
                            $attr['RelatedAttribute']
                            ?? []
                        );
                        if ($relCount > 0):
                    ?>
                        <span class="badge"
                              title="<?= __(
                                  '%s correlation(s)',
                                  $relCount
                              ) ?>">
                            <?= $relCount ?>
                        </span>
                    <?php endif; ?>
                    </td>
                    <td>
                    <?php if ($attr['to_ids']): ?>
                        <i class="fas fa-database"
                           title="<?= __(
                               'IDS flag set'
                           ) ?>"></i>
                    <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <?php else: ?>
            <em><?= __('No visible attributes.') ?></em>
        <?php endif; ?>
    </div>
    <?php endforeach; ?>
<?php else: ?>
    <p><em><?= __(
        'No objects in this event.'
    ) ?></em></p>
<?php endif; ?>

<?php if ($totalPages > 1): ?>
    <div class="pagination"
         style="text-align:center;">
        <?php for ($p = 1; $p <= $totalPages; $p++): ?>
            <?php if ($p === (int)$page): ?>
                <span class="badge badge-inverse">
                    <?= $p ?>
                </span>
            <?php else: ?>
                <a href="#"
                   onclick="loadObjectPage(<?=
                       $p
                   ?>); return false;"
                   class="badge">
                    <?= $p ?>
                </a>
            <?php endif; ?>
        <?php endfor; ?>
    </div>
<?php endif; ?>
</div>

<script>
function loadObjectPage(page) {
    var url = baseurl
        + '/events/viewObjects/<?= h($eventId) ?>'
        + '/page:' + page;
    $.ajax({
        type: 'get',
        url: url,
        beforeSend: function() {
            $('.loading').show();
        },
        success: function(data) {
            $('#objects_panel-collapse-inner')
                .html(data);
        },
        error: function() {
            showMessage(
                'fail',
                'Could not load objects.'
            );
        },
        complete: function() {
            $('.loading').hide();
        }
    });
}
</script>
