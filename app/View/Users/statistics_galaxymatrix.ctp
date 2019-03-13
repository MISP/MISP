<div class = "index">
    <h2><?php echo __('Statistics');?></h2>
    <?php
        echo $this->element('Users/statisticsMenu');
    ?>
    <p style="margin-bottom: 40px;"><?php echo __(sprintf('A heatmap showing the usage of %s.', $galaxyName));?></p>

    <select id="galaxyMatrixPicker" onchange="this.options[this.selectedIndex].value && (window.location = 'galaxy_id:' + this.options[this.selectedIndex].value);" >
        <?php foreach ($matrixGalaxies as $k => $galaxy): ?>
            <option value="<?php echo h($galaxy['Galaxy']['id']); ?>" <?php echo $galaxy['Galaxy']['id'] == $galaxyId ? 'selected' : ''; ?> ><?php echo h($galaxy['Galaxy']['name']); ?></option>
        <?php endforeach; ?>
    </select>

<div id="attackmatrix_div" style="position: relative; border: solid 1px;" class="statistics_attack_matrix">
    <?php
        echo $this->element('view_galaxy_matrix');
    ?>
</div>

</div>

<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'globalActions', 'menuItem' => 'statistics'));
?>
