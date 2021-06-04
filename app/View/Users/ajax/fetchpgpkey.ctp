<div class="popover_choice">
    <legend><?php echo __('Choose the key that you would like to use'); ?></legend>
    <p style="padding:0.3em 10px">
        <?php echo __("Do not blindly trust fetched keys and check the fingerprint from other source.") ?>
        <a href="https://evil32.com" rel="noreferrer noopener" target="_blank"><?php echo __("And do not check just Key ID, but whole fingerprint.") ?></a>
    </p>
    <div class="popover_choice_main" id ="popover_choice_main">
        <table style="width:100%;">
            <tr>
                <th style="padding-left:10px; text-align:left;"><?php echo __('Key ID');?></th>
                <th style="text-align:left;"><?php echo __('Creation date');?></th>
                <th style="padding-right:10px; text-align:left;"><?php echo __('Associated E-mail addresses');?></th>
            </tr>
        <?php foreach ($keys as $key): ?>
            <tr style="border-bottom:1px solid black;cursor:pointer;" class="templateChoiceButton" data-fingerprint="<?php echo h($key['fingerprint']); ?>">
                <td role="button" tabindex="0" aria-label="<?php echo __('Select PGP key');?>" style="padding-left:10px; text-align:left;width:20%;" title="<?php echo h($key['fingerprint']); ?>"><?php echo h($key['key_id']); ?></td>
                <td style="text-align:left;width:20%;" title="<?php echo h($key['fingerprint']); ?>"><?php echo h($key['date']); ?></td>
                <td style="padding-right:10px; text-align:left;width:60%;" title="<?php echo h($key['fingerprint']); ?>">
                    <b><?php echo h(chunk_split($key['fingerprint'], 4, ' ')); ?></b><br />
                    <?php echo nl2br(h($key['address'])); ?>
                </td>
            </tr>
        <?php endforeach; ?>
        </table>
    </div>
    <div role="button" tabindex="0" aria-label="<?php echo __('Cancel');?>" class="templateChoiceButton templateChoiceButtonLast" onClick="cancelPopoverForm();"><?php echo __('Cancel');?></div>
</div>
<script type="text/javascript">
    $(function() {
        resizePopoverBody();

        $('tr[data-fingerprint]').click(function () {
            var fingerprint = $(this).data('fingerprint');
            gpgSelect(fingerprint);
        });
    });

    $(window).resize(function() {
        resizePopoverBody();
    });
</script>
