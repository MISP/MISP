<?php
/**
 * Minimal layout for embedding rendered report previews in iframes.
 * Only includes the essential CSS/JS needed for markdown rendering.
 */
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <?php
        echo $this->Html->css('bootstrap');
        echo $this->Html->css('font-awesome');
        echo $this->Html->css('main');
        echo $this->Html->css('chosen.min');
        echo $this->Html->script('jquery');
        echo $this->Html->script('bootstrap');
        echo $this->Html->script('chosen.jquery.min');
    ?>
    <script>
        var baseurl = '<?= $baseurl ?>';
        // CSRF token for hand-built same-origin AJAX, which has no rendered form
        // to carry _Token fields. Sent as the X-CSRF-Token header - see
        // BetterSecurityComponent::_validateCsrf().
        var csrfToken = <?= json_encode(isset($this->request->params['_Token']['key']) ? $this->request->params['_Token']['key'] : '') ?>;
        function getTextColour(hex) {
            if (hex.indexOf('#') === 0) {
                hex = hex.slice(1);
            }
            if (hex.length === 3) {
                hex = hex[0] + hex[0] + hex[1] + hex[1] + hex[2] + hex[2];
            }
            var r = parseInt(hex.substring(0,2), 16);
            var g = parseInt(hex.substring(2,4), 16);
            var b = parseInt(hex.substring(4,6), 16);
            var avg = ((2 * r) + b + (3 * g))/6;
            if (avg < 128) {
                return 'white';
            } else {
                return 'black';
            }
        }
    </script>
</head>
<body style="margin: 0; padding: 10px; background: #fff; overflow-x: hidden;">
    <?php echo $this->fetch('content'); ?>
</body>
</html>
