<div class="popover_choice">
    <legend><?php echo __('Select Object Category');?></legend>
    <div class="popover_choice_main" id ="popover_choice_main">
        <table style="width:100%;" id="MainTable">
            <tr style="border-bottom:1px solid black;" class="templateChoiceButton">
                <td role="button" tabindex="0" aria-label="<?php echo __('All meta-categories');?>" title="<?php echo __('All Objects');?>" style="padding-left:10px;padding-right:10px; text-align:center;width:100%;" onClick="objectChoiceSelect('all');"><?php echo __('All Objects');?></td>
            </tr>
        </table>
    </div>
    <div role="button" tabindex="0" aria-label="<?php echo __('Cancel');?>" title="<?php echo __('Cancel');?>" class="templateChoiceButton templateChoiceButtonLast" onClick="cancelPopoverForm();"><?php echo __('Cancel');?></div>
</div>
<script type="text/javascript">
    var choice = "categories";
    var eventId = "<?php echo h($eventId);?>";
    var templates = <?php echo json_encode($templates); ?>;
    var template_categories = <?php echo json_encode($template_categories); ?>;
    $(document).ready(function() {
        resizePopoverBody();
        populateObjectChoiceList(choice);
    });

    $(window).resize(function() {
        resizePopoverBody();
    });

    function populateObjectChoiceList(choice) {
        $("#MainTable").empty();
        if (choice == "categories") {
            template_categories.forEach(function(category) {
                $("#MainTable").append(createObjectChoiceRowCategories(category));
            });
        } else {
            templates[choice].forEach(function(element) {
                $("#MainTable").append(createObjectChoiceRow(eventId, element));
            });
            $("#MainTable").append(createObjectChoiceRowCategories('categories'));
        }
    }

    function createObjectChoiceRow(eventId, data) {
        var html = '<tr style="border-bottom:1px solid black;" class="templateChoiceButton">';
        var html = html + '<td role="button" tabindex="0" aria-label="' + data["description"] + '" title="' + data["description"] + '" style="padding-left:10px;padding-right:10px; text-align:center;width:100%;" onClick="window.location=\'/objects/add/' + eventId + '/' + data["id"] + '\';">' + data["name"].charAt(0).toUpperCase() + data["name"].slice(1) + '</td>';
        var html = html + '</tr>';
        return html;
    }

    function createObjectChoiceRowCategories(data) {
        var text = data;
        if (text == 'categories') {
            text = '<?php echo __('Back to categories');?>';
        }
        var html = '<tr style="border-bottom:1px solid black;" class="templateChoiceButton">';
        var html = html + '<td role="button" tabindex="0" aria-label="' + (text[0].toUpperCase() + text.slice(1)) + '" title="' + (text[0].toUpperCase() + text.slice(1)) + '" style="padding-left:10px;padding-right:10px; text-align:center;width:100%;" onClick="populateObjectChoiceList(\'' + data + '\');">' + (text[0].toUpperCase() + text.slice(1)) + '</td>';
        var html = html + '</tr>';
        return html;
    }
</script>
