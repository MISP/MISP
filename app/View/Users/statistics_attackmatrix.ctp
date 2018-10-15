<div class = "index">
    <h2><?php echo __('Statistics');?></h2>
    <?php
        echo $this->element('Users/statisticsMenu');
    ?>
    <p style="margin-bottom: 40px;"><?php echo __('A heatmap showing the usage of ATT&CK Tactic.');?></p>

<div id="attackmatrix_div" style="position: relative; border: solid 1px;" class="statistics_attack_matrix">
    <?php
        echo $this->element('view_mitre_attack_matrix');
    ?>
</div>
    
</div>

<?php
    echo $this->element('side_menu', array('menuList' => 'globalActions', 'menuItem' => 'statistics'));
?>
