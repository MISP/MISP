<?php
    $id = isset($element['id']) ? (string)$element['id'] : '';
    $label = isset($element['label']) ? (string)$element['label'] : $id;
    $help = isset($element['help']) ? (string)$element['help'] : '';
    $mandatory = !empty($element['mandatory']);
    $repeatable = !empty($element['repeatable']);
    $as = isset($element['as']) ? (string)$element['as'] : 'attachment';
?>
<div class="et-field et-file-field" data-et-element-id="<?php echo h($id); ?>"
     data-et-element-type="file_field"
     data-et-mandatory="<?php echo $mandatory ? '1' : '0'; ?>"
     data-et-repeatable="<?php echo $repeatable ? '1' : '0'; ?>"
     data-et-file-as="<?php echo h($as); ?>"
     style="margin:10px 0;">
    <label style="font-weight:600;">
        <?php echo h($label); ?>
        <?php if ($mandatory): ?><span class="red">*</span><?php endif; ?>
        <span style="color:#888; font-size:11px; font-weight:normal;">
            (<?php echo __('stored as %s', h($as)); ?>)
        </span>
    </label>
    <?php if ($help !== ''): ?>
        <div class="et-help" style="color:#666; font-size:12px; margin:2px 0 4px 0;">
            <?php echo $this->EventTemplateMarkdown->render($help); ?>
        </div>
    <?php endif; ?>

    <input type="file" class="et-file-input"
           <?php if ($repeatable): ?>multiple<?php endif; ?>
           data-et-file-target="<?php echo h($id); ?>">
    <div class="et-file-list" data-et-file-list-for="<?php echo h($id); ?>"
         style="margin-top:6px; font-size:12px; color:#555;"></div>
    <?php if ($as === 'malware-sample'): ?>
        <span style="color:#888; font-size:11px;">
            <?php echo __('Files uploaded here are server-side zipped and password-encrypted as MISP malware samples before storage.'); ?>
        </span>
    <?php endif; ?>
</div>
