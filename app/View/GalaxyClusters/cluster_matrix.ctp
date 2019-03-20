<button class="btn btn-inverse" onclick="$('#attackmatrix_div').toggle('blind', 300);"><span class="fa fa-eye-slash"> <?php echo __('Toggle ATT&CK Matrix'); ?></span></button>
<div id="attackmatrix_div" style="position: relative; border: solid 1px;" class="statistics_attack_matrix hidden">
    <?php
        echo $this->element('view_galaxy_matrix');
    ?>
</div>
