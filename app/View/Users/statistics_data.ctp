<?php
    echo $this->Html->script('d3');
    echo $this->Html->script('cal-heatmap');
    echo $this->Html->css('cal-heatmap');
?>
<div class = "index">
<h2><?php echo __('Statistics');?></h2>
<?php
    echo $this->element('Users/statisticsMenu');
?>
<p><?php echo __('Some statistics about this instance. The changes since the beginning of this month are noted in brackets wherever applicable');?></p>
<div style="width:250px;">
    <dl>
        <dt><?php echo __('Events');?></dt>
        <dd><?php echo h($stats['event_count']);
            if ($stats['event_count_month']) echo ' <span style="color:green">(+' . h($stats['event_count_month']) . ')</span>&nbsp;';
            else echo ' <span style="color:red">(0)</span>&nbsp;';?>
        </dd>
        <dt><?php echo __('Attributes'); ?></dt>
        <dd><?php echo h($stats['attribute_count']);
            if ($stats['attribute_count_month']) echo ' <span style="color:green">(+' . h($stats['attribute_count_month']) . ')</span>&nbsp;';
            else echo ' <span style="color:red">(0)</span>&nbsp;';?>
        </dd>
        <dt><?php echo __('Attributes / event'); ?></dt>
        <dd><?php echo h($stats['attributes_per_event']); ?>&nbsp;</dd>
        <dt><?php echo __('Correlations found'); ?></dt>
        <dd><?php echo h($stats['correlation_count']); ?>&nbsp;</dd>
        <dt><?php echo __('Proposals active'); ?></dt>
        <dd><?php echo h($stats['proposal_count']); ?>&nbsp;</dd>
        <dt><?php echo __('Users'); ?></dt>
        <dd><?php echo h($stats['user_count']); ?>&nbsp;</dd>
        <dt><?php echo __('Users with PGP keys'); ?></dt>
        <dd><?php echo h($stats['user_count_pgp']) . ' (' . (round(100*($stats['user_count_pgp'] / $stats['user_count']) ,1)) . '%)'; ?>&nbsp;</dd>
        <dt><?php echo __('Organisations'); ?></dt>
        <dd><?php echo h($stats['org_count']); ?>&nbsp;</dd>
        <dt><?php echo __('Local Organisations'); ?></dt>
        <dd><?php echo h($stats['local_org_count']); ?>&nbsp;</dd>
        <dt><?php echo __('Event creator orgs'); ?></dt>
        <dd><?php echo h($stats['contributing_org_count']); ?>&nbsp;</dd>
        <dt><?php echo __('Average Users / Org'); ?></dt>
        <dd><?php echo h($stats['average_user_per_org']); ?>&nbsp;</dd>
        <dt><?php echo __('Discussion threads'); ?></dt>
        <dd><?php echo h($stats['thread_count']);
            if ($stats['thread_count_month']) echo ' <span style="color:green">(+' . h($stats['thread_count_month']) . ')</span>&nbsp;';
            else echo ' <span style="color:red">(0)</span>&nbsp;';?>
        </dd>
        <dt><?php echo __('Discussion posts'); ?></dt>
        <dd><?php echo h($stats['post_count']);
            if ($stats['post_count_month']) echo ' <span style="color:green">(+' . h($stats['post_count_month']) . ')</span>&nbsp;';
            else echo ' <span style="color:red">(0)</span>&nbsp;';?>
        </dd>
    </dl>
</div>
<br />
<h3><?php echo __('Activity Heatmap');?></h3>
<p><?php echo __('A heatmap showing user activity for each day during this month and the 4 months that preceded it. Use the buttons below to only show the heatmap of a specific organisation.');?></p>
<div id="orgs">
    <select onchange="updateCalendar(this.options[this.selectedIndex].value);">
        <option value="all"><?php echo __('All organisations');?></option>
        <?php foreach ($orgs as $orgId => $orgName): ?>
        <option value="<?php echo h($orgId); ?>"><?php echo h($orgName); ?></option>
        <?php endforeach; ?>
    </select>
</div>
<div>
<table>
<tr>
<td style="vertical-align:top;">
<div style="margin-right:5px;margin-top:40px;"><button id="goLeft" class="btn" onClick="goLeft();" title="<?php echo __('Go left');?>"><span class="icon-arrow-left"></span></button></div>
</td>
<td>
<div id="cal-heatmap"></div>
</td>
<td style="vertical-align:top;">
<div style="margin-left:5px;margin-top:40px;"><button id="goRight" class="btn" onClick="goRight();" title="<?php echo __('Go right');?>"><span class="icon-arrow-right"></span></button></div>
</td>
</tr>
</table>
</div>
<script type="text/javascript">
var cal = new CalHeatMap();
var orgSelected = "all";
cal.init({
    range: 5,
    domain:"month",
    subDomain:"x_day",
    start: new Date(<?php echo $startDateCal; ?>),
    data: "<?= $activityUrl ?>.json",
    highlight: "now",
    domainDynamicDimension: false,
    cellSize: 20,
    cellPadding: 1,
    domainGutter: 10,
    legend: <?php echo $range;?>,
    legendCellSize: 15,
});

function updateCalendar(org) {
    if (org == "all") {
        cal.update("<?= $activityUrl ?>/all.json");
        orgSelected = "all";
    } else {
        cal.update("<?= $activityUrl ?>/"+org+".json");
        orgSelected = org;
    }
}

function goRight() {
    cal.options.data = "<?= $activityUrl ?>/"+orgSelected+".json";
    cal.next();
}

function goLeft() {
    cal.options.data = "<?= $activityUrl ?>/"+orgSelected+".json";
    cal.previous();
}
</script>
<?php
if (preg_match('/(?i)msie [2-9]/',$_SERVER['HTTP_USER_AGENT']) && !strpos($_SERVER['HTTP_USER_AGENT'], 'Opera')) {
    if (preg_match('%(?i)Trident/(.*?).0%', $_SERVER['HTTP_USER_AGENT'], $matches) && isset($matches[1]) && $matches[1] > 5) {
        ?>
            <br /><br /><p style="color:red;font-size:11px;"><?php echo __('The above graph will not work correctly in Compatibility mode. Please make sure that it is disabled in your Internet Explorer settings.');?></p>
        <?php
    } else {
        ?>
            <br /><br /><p style="color:red;font-size:11px;"><?php echo __('The above graph will not work correctly on Internet Explorer 9.0 and earlier. Please download Chrome, Firefox or upgrade to a newer version of Internet Explorer.');?></p>
        <?php
    }
}
?>
</div>
<?= $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'globalActions', 'menuItem' => 'statistics'));
