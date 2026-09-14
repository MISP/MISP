<?php
/*
 * Confirmation of an AI indicator extraction (A4), rendered by
 * EventsController::aiExtractIndicators() on GET into the main modal. The
 * submit POSTs the form by fetch; the controller queries the module while
 * the modal shows a spinner and answers the review screen (the same modal
 * body enrichment results use), which replaces this content. Nothing is
 * saved before that screen is submitted.
 *
 * Set by the controller:
 *   $event          array   the event (id, info)
 *   $reports        int     non-deleted reports on the event
 *   $minConfidence  mixed   Plugin.AI_min_confidence
 *   $timeout        int     Plugin.AI_timeout, seconds
 */
$eventId = (int)$event['Event']['id'];
$threshold = ($minConfidence === null || $minConfidence === '') ? '0.9' : $minConfidence;
$message = __n(
    'The AI module reads the %s report of this event and lists the indicators it finds with a confidence of %s or higher, each tagged ai-computer-assisted. You review the list and remove anything wrong before it is added.',
    'The AI module reads the %s reports of this event and lists the indicators it finds with a confidence of %s or higher, each tagged ai-computer-assisted. You review the list and remove anything wrong before it is added.',
    (int)$reports,
    (int)$reports,
    h($threshold)
);
$warning = __('The module usually answers within a minute, at most %s s; the event is unpublished when you import.', (int)$timeout);
if ((int)$reports === 0) {
    $warning = __('This event has no report: nothing can be extracted.');
}
echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'model' => 'Event',
    'url' => $baseurl . '/events/aiExtractIndicators/' . $eventId,
    'hiddenField' => false,
    'eyebrow' => __('AI actions'),
    'accent' => 'primary',
    'title' => __('Extract indicators with AI'),
    'description' => __('The module reads the event reports and proposes attributes and objects.'),
    'message' => $message,
    'warning' => $warning,
    'submitLabel' => __('Extract'),
    'submitIcon' => 'magnifying-glass',
    'icon' => 'fas fa-robot',
    'meta' => [['label' => __('Event'), 'id' => $eventId]],
    'canProceed' => (int)$reports > 0,
]);
?>
<script>
(function () {
    var form = document.getElementById('PromptForm');
    if (!form) { return; }
    var L = <?= json_encode([
        'waiting' => __('Waiting for the module…'),
        'failed' => __('The extraction failed'),
        'extract' => __('Extract'),
    ], JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    form.addEventListener('submit', async function (e) {
        e.preventDefault();
        var button = form.querySelector('button[type="submit"]');
        if (button) {
            button.disabled = true;
            button.innerHTML = '<span class="spinner-border spinner-border-sm me-1" role="status"></span>' + L.waiting;
        }
        try {
            var response = await fetch(form.getAttribute('action'), {
                method: 'POST',
                body: new FormData(form),
                headers: { 'X-Requested-With': 'XMLHttpRequest' }
            });
            var type = response.headers.get('content-type') || '';
            if (type.indexOf('application/json') !== -1) {
                var data = await response.json();
                throw new Error(typeof data.errors === 'string' ? data.errors : (data.message || L.failed));
            }
            if (!response.ok) {
                throw new Error(response.statusText || L.failed);
            }
            var html = await response.text();
            // The review screen replaces this confirmation in the same modal;
            // its scripts run like openModal() runs them.
            var container = document.getElementById('mainModalBody');
            container.innerHTML = html;
            container.querySelectorAll('script:not([type="application/json"])').forEach(function (oldScript) {
                var script = document.createElement('script');
                if (oldScript.src) {
                    script.src = oldScript.src;
                } else {
                    script.textContent = '(function(){\n' + oldScript.textContent + '\n})();';
                }
                document.body.appendChild(script);
                document.body.removeChild(script);
            });
            setModalSize('xl');
        } catch (err) {
            showToast(L.failed + ': ' + err.message, 'danger');
            if (button) {
                button.disabled = false;
                button.innerHTML = '<i class="fas fa-magnifying-glass me-1"></i>' + L.extract;
            }
        }
    });
})();
</script>
