<?php
    function endsWith($haystack, $needle)
    {
        $length = strlen($needle);
        if ($length == 0) {
            return true;
        }
        return (substr($haystack, -$length) === $needle);
    }
    function preppendScopedId($widgetCSS, $seed)
    {
        $prependSelector = sprintf('[data-scoped="%s"]', $seed);
        $cssLines = explode("\n", $widgetCSS);
        foreach ($cssLines as $i => $line) {
            if (strlen($line) > 0) {
                if (endsWith($line, "{")) {
                    $cssLines[$i] = sprintf("%s %s", $prependSelector, $line);
                }
            }
        }
        $cssScopedLines = implode(PHP_EOL, $cssLines);
        return sprintf("<style>%s%s%s</style>", PHP_EOL, $cssScopedLines, PHP_EOL);
    }

    $widgetHtml = $this->element('/dashboard/Widgets/' . $config['render']);
    $widgetCSS = "";
    $seed = "";
    $styleTag = "<style scoped>";
    $styleClosingTag = "</style>";
    $styleTagIndex = strpos($widgetHtml, $styleTag);
    $closingStyleTagIndex = strpos($widgetHtml, $styleClosingTag) + strlen($styleClosingTag);
    if ($styleTagIndex !== false && $closingStyleTagIndex !== false && $closingStyleTagIndex > $styleTagIndex) { // enforced scoped css
        $seed = rand();
        $widgetCSS = substr($widgetHtml, $styleTagIndex, $closingStyleTagIndex);
        $widgetHtml = str_replace($widgetCSS, "", $widgetHtml); // remove CSS
        $widgetCSS = str_replace($styleTag, "", $widgetCSS);    // remove the style node
        $widgetCSS = str_replace($styleClosingTag, "", $widgetCSS); // remove closing style node
        $widgetCSS = preppendScopedId($widgetCSS, $seed);
    }
?>
<div id="widgetContentInner_<?= h($widget_id) ?>" <?php echo !empty($seed) ? sprintf("data-scoped=\"%s\" ", $seed) : "" ?>>
    <?php
        echo $widgetHtml;
        echo $widgetCSS;
    ?>
</div>
<script type="text/javascript">
    $(document).ready(function() {
        if (<?= $config['autoRefreshDelay'] ? 'true' : 'false' ?>) {
            setTimeout( function(){
                updateDashboardWidget("#widget_<?= h($widget_id) ?>")},
                <?= $config['autoRefreshDelay'] ? $config['autoRefreshDelay'] : 1 ?> * 1000
            );
        }
    });
</script>
