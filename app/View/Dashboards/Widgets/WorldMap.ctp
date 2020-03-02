<?php
    $css_collection = array(
        'jquery-jvectormap-2.0.5'
    );
    $js_collection = array(
        'jquery-jvectormap-2.0.5.min',
        'jquery-jvectormap-world-mill'
    );
    echo $this->element('genericElements/assetLoader', array(
        'css' => $css_collection,
        'js' => $js_collection,
        'meta' => 'icon'
    ));
    $randomNumber = rand();
?>

<div id="world-map-<?= $randomNumber ?>" style="width: 600px; height: 400px"></div>
<script>
    var mapData = <?= json_encode($data['data']); ?>;
    $('#world-map-<?= $randomNumber ?>').vectorMap({
        map: 'world_mill',
        series: {
            regions: [{
                values: mapData,
                scale: ['#F08080', '#8B0000'],
                normalizeFunction: 'polynomial'
            }]
        },
        onRegionTipShow: function(e, el, code) {
            el.html(el.html()+' (<?= h($data['scope']) ?> - '+mapData[code]+')');
        }
    });
    var container = $('#world-map-<?= $randomNumber ?>').parent().parent();

    function resizeDashboardWorldMap() {
        var width = container.width();
        var height = container.height() - 60;
        $('#world-map-<?= $randomNumber ?>').css('width', width + 'px');
        $('#world-map-<?= $randomNumber ?>').css('height', height + 'px');
        $('#world-map-<?= $randomNumber ?>').vectorMap('get','mapObject').updateSize();
    }
    $(document).ready(function() {
        resizeDashboardWorldMap();
    });
</script>
