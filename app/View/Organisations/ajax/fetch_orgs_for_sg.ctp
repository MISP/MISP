<div class="confirmation">
<legend><?php echo __('Select organisations to add');?></legend>
    <div style="padding:10px;">
        <table>
            <tr>
                <td style="width:285px;">
                    <p><?php echo __('Available Organisations');?></p>
                    <select id="leftValues" size="5" multiple style="width:285px;">
                        <?php
                            foreach ($orgs as $org) {
                                echo '<option value="' . h($org['id']) . '" selected>' . h($org['name']) . '</option>';
                            }
                        ?>
                    </select>
                </td>
                <td style="width:100%;text-align:center;">
                    <span class="btn btn-inverse" id="btnLeft">&lt;&lt;</span>
                    <span class="btn btn-inverse" id="btnRight">&gt;&gt;</span>
                </td>
                <td style="width:285px;">
                    <p><?php echo __('Added Organisations');?></p>
                    <select id="rightValues" size="5" multiple style="width:285px;"></select>
                </td>
            </tr>
        </table>
            <span role="button" tabindex="0" aria-label="<?php echo __('Submit organisations');?>" title="<?php echo __('Submit organisations');?>" class="btn btn-primary" style="margin-left:auto;margin-right:auto;width:40px;" onClick="submitPicklistValues('org', '<?php echo h($local);?>');">Add</span>
            <span role="button" tabindex="0" aria-label="<?php echo __('Cancel');?>" title="<?php echo __('Cancel');?>" class="btn btn-inverse" style="float:right;margin-left:auto;margin-right:auto;width:40px;" onClick="cancelPicklistValues();"><?php echo __('Cancel');?></span>
    </div>
</div>
<script>
$("#btnLeft").click(function () {
    var selectedItem = $("#rightValues option:selected");
    $("#leftValues").append(selectedItem);
});

$("#btnRight").click(function () {
    var selectedItem = $("#leftValues option:selected");
    $("#rightValues").append(selectedItem);
});
</script>
