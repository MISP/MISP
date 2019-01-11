<?php
/**
*   Generic pre select picker from JSON
*   Required: $choices
*/
?>

<script>
    function addOptionsToSelect(clicked) {
        var $clicked = $(clicked);
        var $wrapper = $clicked.closest('div').find('div.generic-picker-wrapper');
        $.ajax({
            dataType:"html",
            async: true,
            cache: false,
            beforeSend: function() {
                var loadingHtml = '<div style="height: 40px; width: 40px; left: 50%; position: relative;"><div class="spinner" style="height: 30px; width: 30px;"></div></div>';
                var $arrow = $clicked.closest('div.popover').find('div.arrow');
                syncPopoverArrow($arrow, $wrapper, loadingHtml)
            },
            success:function (data, textStatus) {
                var $arrow = $clicked.closest('div.popover').find('div.arrow');
                syncPopoverArrow($arrow, $wrapper, data)
            },
            error:function() {
                $wrapper.html('<div class="alert alert-error" style="margin-bottom: 0px;">Something went wrong - the queried function returned an exception. Contact your administrator for further details (the exception has been logged).</div>');
            },
            url: $clicked.data('endpoint')
        });
    }

    // Used to keep the popover arrow at the correct place regardless of the popover content
    function syncPopoverArrow($arrow, $wrapper, content) {
        var ar_pos = $arrow.position();
        $wrapper.html(content);
        // redraw popover
        $arrow.css('top', ar_pos.top + 'px');
        $arrow.css('left', ar_pos.left + 'px');
    }

        <?php if ($use_select): ?>
        function setupChosen(id) {
            var $elem = $('#'+id);
            $elem.chosen({disable_search_threshold: 10});
            $elem.change(function(event, selected) {
                select = this;
                $select = $(select);
                $select.data('endpoint', selected.selected);
                addOptionsToSelect($select)
            });
        }
    <?php endif; ?>
</script>


<?php if ($use_select): ?>
    <?php $select_id = h(uniqid()); // used to only register the listener on this select (allowing nesting) ?>
    <select id="<?php echo $select_id; ?>" style="height: 20px; margin-bottom: 0px;">
        <option></option>
        <?php foreach ($choices as $name => $endpoint): ?>
            <option value="<?php echo h($endpoint); ?>"><?php echo h($name); ?></option>
        <?php endforeach; ?>
    </select>
    <script>
        $(document).ready(function() {
            setTimeout(function() { // let time for the popup to show
                setupChosen("<?php echo $select_id; ?>");
            }, 10);
        });
    </script>

<?php else: ?>
    <ul class="nav nav-pills">
        <?php foreach($choices as $name => $endpoint): ?>
            <li>
                <a href="#" data-toggle="pill" class="pill-pre-picker"
                    data-endpoint="<?php echo h($endpoint); ?>"
                    onclick="addOptionsToSelect(this)"
                >
                    <?php echo h($name); ?>
                </a>
            </li>
        <?php endforeach; ?>
    </ul>
<?php endif; ?>
<div class='generic-picker-wrapper'></div>
