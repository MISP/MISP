<?php if (empty($reports)): ?>
    <div class="alert alert-info" style="margin-bottom: 0;">
        <i class="fa fa-info-circle"></i> <?php echo __('No Event Reports found.'); ?>
        <?php if ($mayModify): ?>
            <a href="<?php echo $baseurl; ?>/eventReports/add/<?php echo $event['Event']['id']; ?>" class="btn btn-mini btn-primary pull-right"><i class="fa fa-plus"></i> <?php echo __('Add Report'); ?></a>
        <?php endif; ?>
    </div>
<?php else: ?>
    <div class="beta-report-carousel">
        <?php foreach ($reports as $report): ?>
            <?php 
                $r = $report['EventReport']; 
                // Simple markdown preview extraction
                $preview = '';
                if (!empty($r['content'])) {
                    $preview = strip_tags($r['content']); // Very basic strip, in reality we might want a markdown parser or just take the first few lines
                    if (strlen($preview) > 200) {
                        $preview = substr($preview, 0, 200) . '...';
                    }
                }
            ?>
            <div class="beta-report-card" onclick="openGenericModal('<?php echo $baseurl; ?>/eventReports/viewSummary/<?php echo $r['id']; ?>');">
                <div class="report-header">
                    <span class="report-title"><?php echo h($r['name']); ?></span>
                    <span class="report-date pull-right text-muted"><i class="fa fa-clock"></i> <?php echo h(date('Y-m-d', $r['timestamp'])); ?></span>
                </div>
                <div class="report-preview">
                    <?php echo h($preview); ?>
                    <?php if (empty($preview)): ?>
                        <em class="text-muted"><?php echo __('Click to view report content'); ?></em>
                    <?php endif; ?>
                </div>
                <div class="report-footer">
                    <span class="label label-info"><?php echo h($r['distribution'] == 0 ? 'Org Only' : 'Shared'); ?></span>
                    <i class="fa fa-chevron-right pull-right text-muted"></i>
                </div>
            </div>
        <?php endforeach; ?>
        <?php if ($mayModify): ?>
             <div class="beta-report-card add-new" onclick="window.location='<?php echo $baseurl; ?>/eventReports/add/<?php echo $event['Event']['id']; ?>'">
                <div class="text-center" style="padding-top: 20px;">
                    <i class="fa fa-plus-circle fa-3x text-success"></i><br>
                    <strong><?php echo __('Add New Report'); ?></strong>
                </div>
            </div>
        <?php endif; ?>
    </div>
    
    <style>
        .beta-report-carousel {
            display: flex;
            overflow-x: auto;
            padding-bottom: 10px;
            gap: 15px;
        }
        .beta-report-card {
            background: #fff;
            border: 1px solid #ddd;
            border-radius: 6px;
            min-width: 300px;
            max-width: 300px;
            padding: 15px;
            cursor: pointer;
            transition: all 0.2s;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        .beta-report-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
            border-color: #bbb;
        }
        .report-header {
            margin-bottom: 10px;
            border-bottom: 1px solid #eee;
            padding-bottom: 5px;
        }
        .report-title {
            font-weight: 600;
            color: #333;
            font-size: 14px;
        }
        .report-preview {
            font-size: 12px;
            color: #666;
            height: 60px;
            overflow: hidden;
            margin-bottom: 10px;
            line-height: 1.4;
        }
        .beta-report-card.add-new {
            border-style: dashed;
            background: #fafafa;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .beta-report-card.add-new:hover {
            background: #f0fdf4;
            border-color: #46a546;
        }
    </style>
<?php endif; ?>
