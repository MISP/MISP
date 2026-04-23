<div class="index">
    <h2><?php echo __('Import Event Template'); ?></h2>
    <p class="help-block">
        <?php echo __('The import UI ships in Phase 2 of the event-templating rollout. Until then, import templates via the REST API:'); ?>
    </p>
    <pre>POST <?php echo h($this->Html->url(array('action' => 'import'))); ?>?mode=fail
Content-Type: application/json
Accept: application/json

{ "_meta": { ... }, "template": { ... } }</pre>
    <p><?php echo __('Or upload a JSON file via multipart form data (field name: <code>file</code>).'); ?></p>
    <p>
        <?php echo __('Supported <code>mode</code> query values:'); ?>
    </p>
    <ul>
        <li><code>fail</code> — <?php echo __('(default) abort if a template with the same uuid already exists.'); ?></li>
        <li><code>overwrite</code> — <?php echo __('replace the existing template in place; original ownership is preserved.'); ?></li>
        <li><code>duplicate_as_new</code> — <?php echo __('generate a fresh uuid and save as a new row owned by the importing user.'); ?></li>
    </ul>
    <?php if (!empty($errors)): ?>
        <div class="alert alert-error">
            <?php echo __('Last import failed:'); ?>
            <pre><?php echo h(JsonTool::encode($errors, true)); ?></pre>
        </div>
    <?php endif; ?>
</div>
