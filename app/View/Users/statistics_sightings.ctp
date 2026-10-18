<div class = "index">
    <h2><?php echo __('Statistics');?></h2>
    <?php
        echo $this->element('Users/statisticsMenu');
    ?>
    <p><?php echo __('A toplist of the top sources for the sightings of your organisation.');?></p>
    <table class="table table-striped table-hover table-condensed" style="display:block; overflow-y:auto;width:700px;">
    <tr>
        <th><?php echo __('Source');?></th>
        <th><?php echo __('#Entries');?></th>
        <th><?php echo __('#Sighting');?></th>
        <th><?php echo __('#False-positive');?></th>
        <th><?php echo __('Expiration');?></th>
    </tr>
    <?php
        $count = 0;
        foreach ($toplist as $source => $total):
            if ($count > 9) break;
    ?>
            <tr>
                <td style="width:20%;"><?php echo empty($source) ? __('Undefined') : h($source);?></td>
                <td style="width:20%;"><?php echo h($total);?></td>
                <?php foreach (array('sighting', 'false-positive', 'expiration') as $type): ?>
                <td style="width:20%;"><?php echo isset($data[$source][$type]) ? h($data[$source][$type]) : '0'; ?></td>
                <?php endforeach; ?>
            </tr>
    <?php
            $count++;
        endforeach;
    ?>
    </table>
</div>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'globalActions', 'menuItem' => 'statistics'));
?>
