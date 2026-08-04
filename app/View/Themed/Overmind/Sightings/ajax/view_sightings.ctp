<link rel="stylesheet" href="<?= $baseurl ?>/css/sightingstyle.css">

<div style="overflow-x:auto;">
    <div id="graphContent"></div>
</div>

<script>
(function () {
    /* json_encode turns PHP single-quote \n (backslash+n) into \\n in JSON.
     * sightingsGraph calls d3.csv.parse directly without replaceAll,
     * so we must convert to real newlines before calling it. */
    var csv = <?= json_encode($csv) ?>;
    csv = csv.replaceAll('\\n', '\n');

    function initGraph() {
        if (typeof sightingsGraph === 'function') {
            sightingsGraph('#graphContent', csv);
        }
    }

    function loadScript(src, cb) {
        var s = document.createElement('script');
        s.src = src;
        s.onload = cb;
        document.head.appendChild(s);
    }

    function run() {
        if (typeof d3 === 'undefined') {
            loadScript(baseurl + '/js/d3.js', function () {
                if (typeof sightingsGraph === 'undefined') {
                    loadScript(baseurl + '/js/d3.custom.js', initGraph);
                } else {
                    initGraph();
                }
            });
        } else if (typeof sightingsGraph === 'undefined') {
            loadScript(baseurl + '/js/d3.custom.js', initGraph);
        } else {
            initGraph();
        }
    }

    /* Small delay so the modal is fully painted before D3 measures dimensions */
    setTimeout(run, 50);
})();
</script>
