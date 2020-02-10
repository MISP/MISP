<div class = "index">
    <h2><?php echo __('Statistics');?></h2>
    <?php
        echo $this->element('Users/statisticsMenu');
    ?>
    <p style="margin-bottom: 40px;"><?php echo sprintf(__('A heatmap showing the usage of %s.'), $galaxyName);?></p>

    <div style="height: 80px;">
        <div class="input select">
            <label>Galaxy</label>
            <select id="galaxyMatrixPicker" data-toggle="chosen">
                <?php foreach ($matrixGalaxies as $k => $galaxy): ?>
                    <option value="<?php echo h($galaxy['Galaxy']['id']); ?>" <?php echo $galaxy['Galaxy']['id'] == $galaxyId ? 'selected' : ''; ?> ><?php echo h($galaxy['Galaxy']['name']); ?></option>
                <?php endforeach; ?>
            </select>
        </div>
        <div class="input select">
            <label>Organisation</label>
            <select id="organisationPicker" data-toggle="chosen">
                <?php foreach ($organisations as $k => $org): ?>
                    <option value="<?php echo isset($org['Organisation']['id']) ? h($org['Organisation']['id']) : ''; ?>" <?php echo $org['Organisation']['id'] == $picked_organisation['Organisation']['id'] ? 'selected' : ''; ?> ><?php echo h($org['Organisation']['name']); ?></option>
                <?php endforeach; ?>
            </select>
        </div>
        <div style="display: inline-block;">
            <label>Dates</label>
            <input id="dateFrom" class="datepicker" placeholder="from" value="<?php echo isset($dateFrom) ? h($dateFrom) : ''; ?>">
            <i class="fas fa-arrow-right"></i>
            <input id="dateTo" class="datepicker" placeholder="to" value="<?php echo isset($dateTo) ? h($dateTo) : ''; ?>">
        </div>
        <button id="btnSubmit" class="btn btn-primary"><?php echo __('Submit') ?></button>
    </div>

    <div id="attackmatrix_div" style="position: relative; border: solid 1px;" class="statistics_attack_matrix">
        <?php
            echo $this->element('view_galaxy_matrix');
        ?>
    </div>
</div>

<script>
$(document).ready(function() {
    $('#btnSubmit').click(function() {
        var value = $('#galaxyMatrixPicker').val();
        var organisation = $('#organisationPicker').val();
        var dateFrom = $('#dateFrom').val();
        var dateTo = $('#dateTo').val();
        var eventTagsOnAttributes = $('#eventTagsOnAttributes').is(':checked');
        var url = '<?php echo $baseurl; ?>/users/statistics/galaxyMatrix/galaxy_id:' + value
        if (organisation) {
            url += '/' + 'organisation:' + organisation;
        }
        if (dateFrom) {
            url += '/' + 'dateFrom:' + dateFrom;
        }
        if (dateTo) {
            url += '/' + 'dateTo:' + dateTo;
        }
        $(this).text('').append('<i class="fas fa-spinner fa-spin"></i>')
        window.location = url;
    });

    $('[data-toggle="chosen"]').chosen();

})
</script>

<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'globalActions', 'menuItem' => 'statistics'));
?>
