<div id="temp"></div>
<?php echo $this->element('generic_picker'); ?>
<?php if (!empty($mirrorOnEvent)) : ?>
    <div class="checkbox" style="margin-left: 1em;">
        <input type="checkbox" name="data[Galaxy][mirrorOnEvent]" class="" id="mirrorOnEvent">
        <label for="mirrorOnEvent" style="display: inline-block;"><?= __('Tag the event as well') ?></label>
    </div>
<?php endif; ?>
<script>
    $(function() {
        $('#GalaxyAttributeIds').attr('value', getSelected());
        $('#mirrorOnEvent').change(function() {
            var $select = $(this).closest('.generic-picker-wrapper').find('select')
            var additionalData = $select.data('additionaldata');
            additionalData['mirrorOnEvent'] = $(this).prop('checked')
            $select.data('additionaldata', JSON.stringify(additionalData))
        })
    });
</script>
