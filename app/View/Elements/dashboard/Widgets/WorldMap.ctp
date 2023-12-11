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
    if (!empty($config['widget_config']['colour_scale'])) {
        $data['colour_scale'] = json_encode($config['widget_config']['colour_scale']);
    }
    if (empty($data['colour_scale'])) {
        // Rainbow colour scale
        // $data['colour_scale'] = json_encode(array(
        //     '#003FBF','#0063BF','#0087BF','#00ACBF','#00BFAD','#00BF89','#00BF64',
        //     '#00BF40','#00BF1C','#08BF00','#2CBF00','#51BF00','#75BF00','#99BF00',
        //     '#BEBF00','#BF9B00','#BF7700','#BF5200','#BF2E00','#BF0900'
        // ), true);
        // Yellow to red
        // $data['colour_scale'] = '["#fce94f", "#f7d949", "#f2c943", "#edb83c", "#e7a735", "#e0962e", "#d98427", "#d1711f", "#c75d17", "#bd470e", "#b12d05", "#a40000"]';
        // Blue to purple
        $data['colour_scale'] = '["#2fa1db","#3e95cd","#4689c0","#4b7eb4","#4d73a8","#4e679c","#4d5b90","#4b4f85","#494279","#45346f","#402464","#3c0f59"]';
        // Red to red
        // $data['colour_scale'] = '["#fdf5f5", "#fce9e9", "#fae0e0", "#f8d3d3", "#f1a7a7", "#ea7b7b", "#e34f4f", "#dc2323", "#c61f1f", "#b01c1c", "#841515", "#580e0e", "#2c0707"]';
    }
?>
<div id="world-map-<?= $randomNumber ?>" style="width: 600px; height: 400px"></div>
<script>
    (function() { // variables and functions have their own scope (no override)
        'use strict';
        var randomNumber = "<?= $randomNumber ?>";
        var scope = "<?= h($data['scope']) ?>";
        var resize_timeout;
        var mapData = <?= json_encode($data['data']); ?>;
        var $worldmap = $('#world-map-'+randomNumber);
        var $container = $worldmap.closest('div.widgetContent');
        $worldmap.vectorMap({
            map: 'world_mill',
            series: {
                regions: [{
                    values: mapData,
                    scale:
                    <?= $data['colour_scale'] ?>, //  gradient blue->green->yellow->red
                    normalizeFunction: 'polynomial',
                    legend: {
                        vertical: false,
                        labelRender: function(v){
                            return Math.round(v);
                        }
                    }
                }]
            },
            onRegionTipShow: function(e, el, code) {
                var amount = mapData[code] !== undefined ? mapData[code] : 0; // no data defaulted to 0
                el.html(el.html()+' (' + scope + ' - '+amount+')');
            }
        });

        function resizeDashboardWorldMap() {
            var width = $container.width();
            var height = $container.height();
            $worldmap
                .css('width', width + 'px')
                .css('height', height + 'px')
                .vectorMap('get','mapObject').updateSize();
        }
        $(document).ready(function() {
            resizeDashboardWorldMap();
            window.addEventListener("resize", function() {
                if (resize_timeout !== undefined) {
                    clearTimeout(resize_timeout);
                }
                resize_timeout = setTimeout(function() { resizeDashboardWorldMap() }, 500); // redraw after 500ms
            });
            $worldmap.closest('.widgetContentInner').on('widget-resized', function() {
                resizeDashboardWorldMap();
            })
        });
    }());
</script>
