<?php
$paging = $this->params['paging']['AuditLog'];
$betaCurrentPage = $paging['page'];
$betaTotalPages = $paging['pageCount'];
$betaTotalItems = $paging['count'];
$betaPageSize = $paging['limit'];
$betaShowStart = ($betaTotalItems > 0) ? ($betaCurrentPage - 1) * $betaPageSize + 1 : 0;
$betaShowEnd = min($betaCurrentPage * $betaPageSize, $betaTotalItems);
?>

<style>
    /* Ensure pagination styles are available even if Data tab isn't loaded */
    .beta-pagination-container {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 10px 0;
        margin-bottom: 15px;
        border-bottom: 1px solid #eee;
    }
    .beta-pagination-info {
        font-size: 13px;
        color: #666;
    }
    .beta-pagination-info .beta-page-badge {
        display: inline-block;
        background: #428bca;
        color: #fff;
        padding: 2px 10px;
        border-radius: 3px;
        font-weight: 600;
        font-size: 12px;
    }
    .beta-pagination-controls {
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .beta-pagination-controls .btn {
        min-width: 36px;
    }
    .beta-pagination-controls .beta-page-size-select {
        width: auto;
        display: inline-block;
        padding: 4px 8px;
        font-size: 12px;
        height: auto;
    }
    .beta-pagination-bottom {
        margin-top: 15px;
        padding-top: 10px;
        border-top: 1px solid #eee;
        border-bottom: none;
    }
    .beta-history-action-cell {
        width: 130px;
        min-width: 130px;
        white-space: normal;
    }
    .beta-history-action-badge {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        max-width: 100%;
        font-size: 10px;
        line-height: 1.2;
        text-transform: uppercase;
        padding: 3px 8px;
        white-space: normal;
        word-break: break-word;
        text-align: center;
    }
</style>

<div class="beta-history-container">
    <!-- Pagination Top -->
    <div class="beta-pagination-container" id="beta-history-pagination-top">
        <div class="beta-pagination-info">
            <span class="beta-page-badge"><?php echo __('Page %s of %s', $betaCurrentPage, $betaTotalPages); ?></span>
            <span>(<?php echo __('Showing %s-%s of %s items', $betaShowStart, $betaShowEnd, $betaTotalItems); ?>)</span>
        </div>
        <div class="beta-pagination-controls">
            <button type="button" class="btn btn-default btn-sm beta-history-page-btn" data-page="1" title="<?php echo __('First page'); ?>" <?php if ($betaCurrentPage <= 1) echo 'disabled'; ?>><i class="fa fa-angle-double-left"></i></button>
            <button type="button" class="btn btn-default btn-sm beta-history-page-btn" data-page="<?php echo $betaCurrentPage - 1; ?>" title="<?php echo __('Previous page'); ?>" <?php if ($betaCurrentPage <= 1) echo 'disabled'; ?>><i class="fa fa-angle-left"></i></button>
            <span style="font-size: 12px; color: #666; min-width: 60px; text-align: center;"><?php echo __('%s / %s', $betaCurrentPage, $betaTotalPages); ?></span>
            <button type="button" class="btn btn-default btn-sm beta-history-page-btn" data-page="<?php echo $betaCurrentPage + 1; ?>" title="<?php echo __('Next page'); ?>" <?php if ($betaCurrentPage >= $betaTotalPages) echo 'disabled'; ?>><i class="fa fa-angle-right"></i></button>
            <button type="button" class="btn btn-default btn-sm beta-history-page-btn" data-page="<?php echo $betaTotalPages; ?>" title="<?php echo __('Last page'); ?>" <?php if ($betaCurrentPage >= $betaTotalPages) echo 'disabled'; ?>><i class="fa fa-angle-double-right"></i></button>
            
            <select class="form-control beta-page-size-select" id="beta-history-page-size" title="<?php echo __('Items per page'); ?>">
                <option value="20" <?php echo $betaPageSize == 20 ? 'selected' : ''; ?>>20</option>
                <option value="50" <?php echo $betaPageSize == 50 ? 'selected' : ''; ?>>50</option>
                <option value="100" <?php echo $betaPageSize == 100 ? 'selected' : ''; ?>>100</option>
            </select>
        </div>
    </div>

    <table class="beta-attr-table">
        <thead>
            <tr>
                <th style="width: 130px;"><?php echo __('Time'); ?></th>
                <th style="width: 120px;"><?php echo __('User'); ?></th>
                <th style="width: 100px;"><?php echo __('Org'); ?></th>
                <th style="width: 130px;"><?php echo __('Action'); ?></th>
                <th style="width: 110px;"><?php echo __('Model'); ?></th>
                <th style="width: 250px;"><?php echo __('Object'); ?></th>
                <th><?php echo __('Changes'); ?></th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($data as $item): ?>
                <tr class="beta-attr-row">
                    <td>
                        <div class="beta-relative-timestamp" 
                             data-timestamp="<?= strtotime($item['AuditLog']['created']) ?>"
                             data-absolute="<?= h($item['AuditLog']['created']) ?>"
                             title="<?= h($item['AuditLog']['created']) ?>">
                            <?php echo $this->Time->time($item['AuditLog']['created']); ?>
                        </div>
                    </td>
                    <td>
                        <?php if (!empty($item['User']['email'])): ?>
                            <span class="beta-user-email" title="<?= h($item['User']['email']) ?>">
                                <?= h(explode('@', $item['User']['email'])[0]) ?>
                            </span>
                        <?php else: ?>
                            <span class="muted">SYSTEM</span>
                        <?php endif; ?>
                    </td>
                    <td>
                        <span class="beta-org-name" style="font-size: 11px; color: #666;">
                            <?= !empty($item['Organisation']['name']) ? h($item['Organisation']['name']) : '' ?>
                        </span>
                    </td>
                    <td class="beta-history-action-cell">
                        <?php
                            $actionClass = 'label-default';
                            $action = $item['AuditLog']['action'];
                            if (strpos($action, 'add') !== false) $actionClass = 'label-success';
                            if (strpos($action, 'edit') !== false) $actionClass = 'label-info';
                            if (strpos($action, 'delete') !== false) $actionClass = 'label-danger';
                            if (strpos($action, 'tag') !== false) $actionClass = 'label-warning';
                            if (strpos($action, 'publish') !== false) $actionClass = 'label-primary';
                        ?>
                        <span class="label <?= $actionClass ?> beta-history-action-badge">
                            <?= h($item['AuditLog']['action_human']) ?>
                        </span>
                    </td>
                    <td>
                        <span class="beta-model-name" style="font-weight: 600; font-size: 11px; color: #666; text-transform: uppercase;">
                            <?= h($item['AuditLog']['model']) ?>
                        </span>
                    </td>
                    <td>
                        <div class="beta-object-title" style="font-size: 13px; font-weight: 600; color: #333; word-break: break-all;">
                            <?= h($item['AuditLog']['model_title']) ?>
                        </div>
                    </td>
                    <td>
                        <div class="beta-change-details" style="font-size: 11px; color: #666;">
                            <?php 
                            $change = $item['AuditLog']['change'];
                            if (is_string($change) && !empty($change) && ($change[0] === '{' || $change[0] === '[')) {
                                $change = json_decode($change, true);
                            }
                            
                            if (is_array($change)): ?>
                                <div class="beta-change-list">
                                    <?php foreach ($change as $field => $values): ?>
                                        <div class="beta-change-item" style="margin-bottom: 2px;">
                                            <span style="font-weight: 600; color: #888;"><?= h($field) ?>:</span>
                                            <?php 
                                            if (is_array($values)): 
                                                $old = isset($values[0]) ? $values[0] : '';
                                                $new = isset($values[1]) ? $values[1] : (isset($values[0]) ? $values[0] : '');
                                                ?>
                                                <span class="text-muted" style="text-decoration: line-through; opacity: 0.6;"><?= h(is_array($old) ? json_encode($old) : $old) ?></span>
                                                <i class="fa fa-arrow-right" style="font-size: 9px; margin: 0 4px; color: #ccc;"></i>
                                                <span style="color: #444;"><?= h(is_array($new) ? json_encode($new) : $new) ?></span>
                                            <?php else: ?>
                                                <span style="color: #444;"><?= h($values) ?></span>
                                            <?php endif; ?>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            <?php elseif (!empty($change)): ?>
                                <div class="beta-change-text" style="font-family: monospace; white-space: pre-wrap;"><?= h($change) ?></div>
                            <?php endif; ?>
                        </div>
                    </td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>

    <!-- Pagination Bottom -->
    <div class="beta-pagination-container beta-pagination-bottom" id="beta-history-pagination-bottom">
        <div class="beta-pagination-info">
            <span class="beta-page-badge"><?php echo __('Page %s of %s', $betaCurrentPage, $betaTotalPages); ?></span>
            <span>(<?php echo __('Showing %s-%s of %s items', $betaShowStart, $betaShowEnd, $betaTotalItems); ?>)</span>
        </div>
        <div class="beta-pagination-controls">
            <button type="button" class="btn btn-default btn-sm beta-history-page-btn" data-page="1" title="<?php echo __('First page'); ?>" <?php if ($betaCurrentPage <= 1) echo 'disabled'; ?>><i class="fa fa-angle-double-left"></i></button>
            <button type="button" class="btn btn-default btn-sm beta-history-page-btn" data-page="<?php echo $betaCurrentPage - 1; ?>" title="<?php echo __('Previous page'); ?>" <?php if ($betaCurrentPage <= 1) echo 'disabled'; ?>><i class="fa fa-angle-left"></i></button>
            <span style="font-size: 12px; color: #666; min-width: 60px; text-align: center;"><?php echo __('%s / %s', $betaCurrentPage, $betaTotalPages); ?></span>
            <button type="button" class="btn btn-default btn-sm beta-history-page-btn" data-page="<?php echo $betaCurrentPage + 1; ?>" title="<?php echo __('Next page'); ?>" <?php if ($betaCurrentPage >= $betaTotalPages) echo 'disabled'; ?>><i class="fa fa-angle-right"></i></button>
            <button type="button" class="btn btn-default btn-sm beta-history-page-btn" data-page="<?php echo $betaTotalPages; ?>" title="<?php echo __('Last page'); ?>" <?php if ($betaCurrentPage >= $betaTotalPages) echo 'disabled'; ?>><i class="fa fa-angle-double-right"></i></button>
        </div>
    </div>
</div>

<script>
    if (window.eventTimestamps && typeof window.eventTimestamps.update === 'function') {
        window.eventTimestamps.update();
    }
    
    // Intercept pagination clicks to use AJAX
    $('.beta-history-page-btn').off('click').on('click', function(e) {
        e.preventDefault();
        if ($(this).prop('disabled')) return;
        
        var page = $(this).data('page');
        var limit = $('#beta-history-page-size').val();
        var eventId = '<?php echo h($eventId); ?>';
        var url = "<?php echo $baseurl; ?>/audit_logs/eventIndex/" + eventId + "/page:" + page + "/limit:" + limit;
        
        loadHistoryAjax(url);
    });
    
    $('#beta-history-page-size').off('change').on('change', function() {
        var page = 1;
        var limit = $(this).val();
        var eventId = '<?php echo h($eventId); ?>';
        var url = "<?php echo $baseurl; ?>/audit_logs/eventIndex/" + eventId + "/page:" + page + "/limit:" + limit;
        
        loadHistoryAjax(url);
    });
    
    function loadHistoryAjax(url) {
        $('#history-content-container').addClass('loading-mask').css('opacity', '0.5');
        $.get(url, function(data) {
            $('#history-content-container').html(data).removeClass('loading-mask').css('opacity', '1');
            // Scroll to top of history tab
            $('html, body').animate({
                scrollTop: $("#history").offset().top - 20
            }, 300);
        });
    }
</script>
