<?php
    echo $this->Html->script('d3');
    echo $this->Html->script('cal-heatmap');
    echo $this->Html->css('cal-heatmap');
?>
<div class = "index">
    <h2><?php echo __('Statistics');?></h2>
    <?php
        echo $this->element('Users/statisticsMenu');
        $types = array(
                'local' => array('selected' => false, 'text' => __('Local organisations')),
                'external' => array('selected' => false, 'text' => __('Known remote organisations')),
                'all' => array('selected' => false, 'text' => __('All organisations'))
        );
        if (isset($types[$scope])) {
            $types[$scope]['selected'] = true;
        }
    ?>
    <h4><?php echo __('Organisation list');?></h4>
    <p><?php echo __('Quick overview over the organisations residing on or known by this instance.');?></p>
    <div class="tabMenuFixedContainer" style="display:inline-block;">
            <?php
                foreach ($types as $key => $value):
            ?>
                <span class="tabMenuFixed tabMenuFixedCenter tabMenuSides useCursorPointer <?php if ($value['selected']) echo 'tabMenuActive'; ?>" onclick="window.location='/users/statistics/orgs/scope:<?php echo h($key);?>'"><?php echo h($value['text']); ?></span>
            <?php
                endforeach;
            ?>
    </div>
    <table class="table table-striped table-hover table-condensed" style="width:50%;">
    <tr>
            <th><?php echo __('Logo');?></th>
            <th><?php echo __('Name');?></th>
            <th><?php echo __('Users');?></th>
            <th><?php echo __('Events');?></th>
            <th><?php echo __('Attributes');?></th>
            <th><?php echo __('Nationality');?></th>
            <th><?php echo __('Type');?></th>
            <th><?php echo __('Sector');?></th>
            <th><?php echo __('Activity (1 year)');?></th>
    </tr>
    <?php
        foreach ($orgs as $data):
    ?>
        <tr class="org_row" data-orgid="<?php echo h($data['id']); ?>">
            <td class="short">
                <?php
                    echo $this->OrgImg->getOrgImg(array('name' => $data['name'], 'id' => $data['id'], 'size' => 24));
                ?>
            </td>
            <td class="short"><?php echo h($data['name']); ?></td>
            <td class="short"><span class="<?php echo isset($data['userCount']) ? 'blue bold' : 'grey'; ?>"><?php echo isset($data['userCount']) ? h($data['userCount']) : '0';?></span></td>
            <td class="short"><span class="<?php echo isset($data['eventCount']) ? 'blue bold' : 'grey'; ?>"><?php echo isset($data['eventCount']) ? h($data['eventCount']) : '0';?></span></td>
            <td class="short"><span class="<?php echo isset($data['attributeCount']) ? 'blue bold' : 'grey'; ?>"><?php echo isset($data['attributeCount']) ? h($data['attributeCount']) : '0';?></span></td>
            <td class="shortish"><?php echo isset($data['nationality']) && $data['nationality'] !== 'Not specified' ? h($data['nationality']) : '&nbsp;'; ?></td>
            <td class="shortish"><?php echo isset($data['type']) ? h($data['type']) : '&nbsp;'; ?></td>
            <td class="shortish"><?php echo isset($data['sector']) ? h($data['sector']) : '&nbsp;'; ?></td>
            <td class="shortish">
                <?php
                    if (isset($data['orgActivity'])) {
                        echo $this->element('sparkline', array('scope' => 'organisation', 'id' => $data['id'], 'csv' => $data['orgActivity']['csv']));
                    }
                ?>
            </td>
        </tr>
    <?php
        endforeach;
    ?>
    </table>
</div>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'globalActions', 'menuItem' => 'statistics'));
?>
<script type="text/javascript">
    $('.org_row').click(function() {
        window.location = "<?php echo $baseurl; ?>/organisations/view/" + $(this).data('orgid');
    });
</script>
