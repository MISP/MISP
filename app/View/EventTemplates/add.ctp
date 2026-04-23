<div class="index">
    <h2><?php echo __('Add Event Template'); ?></h2>
    <p class="help-block">
        <?php echo __('The visual builder ships in Phase 2.1 of the event-templating rollout. Until then, create templates via the REST API:'); ?>
    </p>
    <pre>POST <?php echo h($this->Html->url(array('action' => 'add'))); ?>
Content-Type: application/json
Accept: application/json

{
  "name": "...",
  "description": "...",
  "distribution": 0,
  "active": 1,
  "definition": { ... }
}</pre>
    <?php if (!empty($errors)): ?>
        <div class="alert alert-error">
            <?php echo __('Validation errors from your last attempt:'); ?>
            <pre><?php echo h(JsonTool::encode($errors, true)); ?></pre>
        </div>
    <?php endif; ?>
</div>
