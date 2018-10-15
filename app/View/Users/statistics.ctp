<?php
    echo $this->Html->script('d3');
    echo $this->Html->script('cal-heatmap');
    echo $this->Html->css('cal-heatmap');
?>
<div class = "index">
<h2><?php echo __('Statistics');?></h2>
<p><?php echo __('Some statistics about this instance. The changes since the beginning of this month are noted in brackets wherever applicable');?></p>
<div style="width:250px;">
    <dl>
        <dt><?php echo __('Events');?></dt>
        <dd><?php echo h($stats[0]);
            if ($stats[1]) echo ' <span style="color:green">(+' . h($stats[1]) . ')</span>&nbsp;';
            else echo ' <span style="color:red">(0)</span>&nbsp;';?>
        </dd>
        <dt><?php echo __('Attributes'); ?></dt>
        <dd><?php echo h($stats[2]);
            if ($stats[1]) echo ' <span style="color:green">(+' . h($stats[3]) . ')</span>&nbsp;';
            else echo ' <span style="color:red">(0)</span>&nbsp;';?>
        </dd>
        <dt><?php echo __('Correlations found'); ?></dt>
        <dd><?php echo h($stats[4]); ?>&nbsp;</dd>
        <dt><?php echo __('Proposals active'); ?></dt>
        <dd><?php echo h($stats[5]); ?>&nbsp;</dd>
        <dt><?php echo __('Users'); ?></dt>
        <dd><?php echo h($stats[6]); ?>&nbsp;</dd>
        <dt><?php echo __('Organisations'); ?></dt>
        <dd><?php echo h($stats[7]); ?>&nbsp;</dd>
        <dt><?php echo __('Discussion threads'); ?></dt>
        <dd><?php echo h($stats[8]);
            if ($stats[9]) echo ' <span style="color:green">(+' . h($stats[9]) . ')</span>&nbsp;';
            else echo ' <span style="color:red">(0)</span>&nbsp;';?>
        </dd>
        <dt><?php echo __('Discussion posts'); ?></dt>
        <dd><?php echo h($stats[10]);
            if ($stats[11]) echo ' <span style="color:green">(+' . h($stats[11]) . ')</span>&nbsp;';
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
        <?php
            foreach ($orgs as $org):
                ?>
                    <option value="<?php echo h($org['Organisation']['name']); ?>"><?php echo h($org['Organisation']['name']); ?></option>
                <?php
            endforeach;
        ?>
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
    data: "<?php echo Configure::read('MISP.baseurl'); ?>/logs/returnDates.json",
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
        cal.update("<?php echo Configure::read('MISP.baseurl'); ?>/logs/returnDates/all.json");
        orgSelected = "all";
    } else {
        cal.update("<?php echo Configure::read('MISP.baseurl'); ?>/logs/returnDates/"+org+".json");
        orgSelected = org;
    }
}

function goRight() {
    cal.options.data = "<?php echo Configure::read('MISP.baseurl'); ?>/logs/returnDates/"+orgSelected+".json";
    cal.next();
}

function goLeft() {
    cal.options.data = "<?php echo Configure::read('MISP.baseurl'); ?>/logs/returnDates/"+orgSelected+".json";
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
<?php
    echo $this->element('side_menu', array('menuList' => 'globalActions', 'menuItem' => 'statistics'));
?>
