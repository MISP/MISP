<h4 class="blue"><?php echo __('Galaxies');?></h4>
<?php
    $mayModify = (
        ($isAclModify && $object['Event']['orgc_id'] == $me['org_id'])
    );
    if ($scope == 'event') {
        $element = 'galaxyQuickView';
    } else if ($scope == 'attribute') {
        $element = 'galaxyQuickViewMini';
    }
    echo $this->element($element, array(
        'mayModify' => $mayModify,
        'isAclTagger' => $isAclTagger,
        'data' => $object['Galaxy'],
        'target_id' => $object['Event']['id'],
        'target_type' => $scope
    ));
?>
<script type="text/javascript">
    var showContext = false;
    $(document).ready(function () {
        $('.addGalaxy').click(function() {
            addGalaxyListener(this);
        });
    });
</script>
