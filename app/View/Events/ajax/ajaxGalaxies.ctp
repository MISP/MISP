<?php
$mayModify = ($isAclModify && $object['Event']['orgc_id'] == $me['org_id']);
if ($scope === 'event') {
    echo '<span class="title-section">' . __('Galaxies') . '</span>';
}
echo $this->element('galaxyQuickViewNew', [
    'mayModify' => $mayModify,
    'isAclTagger' => $isAclTagger,
    'data' => $object['Galaxy'],
    'event' => $object,
    'target_id' => $scope == 'event' ? $object['Event']['id'] : $object['Attribute']['id'],
    'target_type' => $scope
]);
?>
<script type="text/javascript">
    var showContext = false;
    $(function () {
        $('.addGalaxy').click(function() {
            addGalaxyListener(this);
        });
    });
</script>
