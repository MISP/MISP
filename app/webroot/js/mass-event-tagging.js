/**
 * Bulk Add / Remove Tags on the Events index.
 *
 * Loaded only on /events/index (see the include in app/View/Events/index.ctp).
 * Reuses MISP's native tag picker and submit path rather than intercepting raw
 * AJAX, so CSRF tokens, payload format, and ACL checks are all handled by core.
 *
 * Mechanism (verified against MISP 2.5.40 source):
 *   - The native picker (getPopup(id,'tags','selectTaxonomy')) calls the global
 *     quickSubmitTagForm(selectedTagIds, addData) when the user picks a tag.
 *   - We wrap that function once. While "mass mode" is armed we ignore the
 *     single picker event and instead loop over every selected event, fetching
 *     a fresh CSRF-bearing form per request via the native helpers
 *     (fetchFormDataAjax + xhr) — identical to how core tags one event.
 *   - addTag accepts a JSON array of tag ids, so multi-tag / tag-collections
 *     work for free. removeTag is one tag id per call, handled via the native
 *     GET-confirm-form -> POST flow (also fresh-token per request).
 *
 * Row checkboxes: ".select" with data-id = event id, data-can-modify="1".
 * Native anchor for button placement: "#multi-delete-button".
 */
(function () {
    'use strict';

    $(document).ready(function () {
        if (window.location.pathname.indexOf('/events') === -1) return;
        if (typeof quickSubmitTagForm !== 'function') return; // core helper absent -> no-op

        var state = { mode: null, eventIds: [] }; // mode: 'add' | 'remove' | null

        // ---------------------------------------------------------------------
        // Button injection (next to native Delete button), idempotent + re-runs
        // after table redraws.
        // ---------------------------------------------------------------------
        function injectButtons() {
            if ($('#massTagGroup').length) return;
            var $del = $('#multi-delete-button');
            if (!$del.length) return;

            // Match the native toolbar buttons exactly: icon-only <a> tags with
            // classes "btn btn-small btn-inverse" and a title tooltip, rendered
            // by app/View/Elements/genericElements/ListTopBar/element_simple.ctp.
            $del.closest('.btn-group').after(
                '<div id="massTagGroup" class="btn-group hidden">' +
                    '<a id="mass-add-tag-btn" class="btn btn-small btn-inverse" href="#" ' +
                            'title="Add a tag to all selected events" ' +
                            'aria-label="Add a tag to all selected events">' +
                        '<i class="fa fa-tag"></i></a>' +
                    '<a id="mass-remove-tag-btn" class="btn btn-small btn-inverse" href="#" ' +
                            'title="Remove a tag from all selected events" ' +
                            'aria-label="Remove a tag from all selected events">' +
                        '<i class="fa fa-eraser"></i></a>' +
                '</div>'
            );
            refreshVisibility();
        }
        injectButtons();
        $(document).ajaxComplete(function () { injectButtons(); });

        // ---------------------------------------------------------------------
        // Visibility: show whenever at least one event is checked.
        // ---------------------------------------------------------------------
        function refreshVisibility() {
            $('#massTagGroup').toggleClass('hidden', $('.select:checked').length === 0);
        }
        $(document).on('change click', '.select, .select-all, #select_all, input[type=checkbox]', function () {
            setTimeout(refreshVisibility, 50);
        });

        // ---------------------------------------------------------------------
        // Collect selected event ids (only those the user may modify).
        // ---------------------------------------------------------------------
        function selectedEventIds() {
            var ids = [];
            $('.select:checked').each(function () {
                if (!$(this).data('can-modify')) return;
                var id = $(this).data('id');
                if (id !== undefined && id !== null) ids.push(String(id));
            });
            return ids;
        }

        // ---------------------------------------------------------------------
        // Arm mass mode and open the native tag picker.
        // getPopup(id, context, target) -> baseurl/tags/selectTaxonomy/<id>
        // ---------------------------------------------------------------------
        function openPicker(mode) {
            var ids = selectedEventIds();
            if (!ids.length) { showMessage('fail', 'No modifiable events selected.'); return; }
            state.mode = mode;
            state.eventIds = ids;
            getPopup(ids[0], 'tags', 'selectTaxonomy');
        }
        $(document).on('click', '#mass-add-tag-btn', function (e) { e.preventDefault(); openPicker('add'); });
        $(document).on('click', '#mass-remove-tag-btn', function (e) { e.preventDefault(); openPicker('remove'); });

        // ---------------------------------------------------------------------
        // Wrap the native submit handler exactly once. When mass mode is armed,
        // hijack the chosen tag(s) and fan out across all selected events.
        // Otherwise defer to native behaviour untouched.
        // ---------------------------------------------------------------------
        var nativeQuickSubmitTagForm = quickSubmitTagForm;
        window.quickSubmitTagForm = function (selected_tag_ids, addData) {
            if (!state.mode) return nativeQuickSubmitTagForm.apply(this, arguments);

            var mode   = state.mode;
            var events = state.eventIds.slice();
            var local  = !!(addData && addData.local);
            state.mode = null;
            state.eventIds = [];

            var tagIds = Array.isArray(selected_tag_ids) ? selected_tag_ids.slice() : [selected_tag_ids];
            tagIds = tagIds.filter(function (t) { return t !== null && t !== undefined && t !== ''; });
            if (!events.length || !tagIds.length) return;

            if (mode === 'add') massAdd(events, tagIds, local);
            else                massRemove(events, tagIds);
        };

        // ---------------------------------------------------------------------
        // ADD: per event, fetch a fresh CSRF form, set the tag(s), POST.
        // Sequential to keep one clean token cycle per request.
        // ---------------------------------------------------------------------
        function massAdd(events, tagIds, local) {
            var total = events.length, done = 0, fails = 0, queue = events.slice();
            showMessage('success', 'Applying tag to ' + total + ' event(s)...');
            $('.loading').show();

            (function next() {
                if (!queue.length) return finish();
                var id  = queue.shift();
                var url = '/events/addTag/' + id + (local ? '/local:1' : '');
                fetchFormDataAjax(baseurl + url, function (formHtml) {
                    var $form = $(formHtml);
                    $form.find('#EventTag').val(JSON.stringify(tagIds));
                    xhr({
                        data: $form.serialize(), type: 'post', url: url,
                        success: function () { done++; },
                        error:   function () { fails++; },
                        complete: next
                    });
                }, function () { fails++; next(); });
            })();

            function finish() {
                $('.loading').hide();
                showMessage(fails ? 'fail' : 'success',
                    'Tagged ' + done + '/' + total + ' event(s)' + (fails ? ' (' + fails + ' failed)' : '') + '.');
                setTimeout(function () { window.location.reload(); }, 700);
            }
        }

        // ---------------------------------------------------------------------
        // REMOVE: per (event, tag), GET confirm form (fresh token) then POST it.
        // removeTag takes one numeric tag id per call -> expand events x tags.
        // ---------------------------------------------------------------------
        function massRemove(events, tagIds) {
            var jobs = [];
            events.forEach(function (ev) { tagIds.forEach(function (tg) { jobs.push({ ev: ev, tg: tg }); }); });
            var total = jobs.length, done = 0, fails = 0;
            showMessage('success', 'Removing tag from ' + events.length + ' event(s)...');
            $('.loading').show();

            (function next() {
                if (!jobs.length) return finish();
                var job = jobs.shift();
                var url = '/events/removeTag/' + job.ev + '/' + job.tg;
                $.get(baseurl + url)
                    .done(function (data) {
                        var $form = $('<div>').html(data).find('#PromptForm');
                        if (!$form.length) { fails++; return next(); } // tag not on this event
                        xhr({
                            data: $form.serialize(), type: 'post', url: url,
                            success: function () { done++; },
                            error:   function () { fails++; },
                            complete: next
                        });
                    })
                    .fail(function () { fails++; next(); });
            })();

            function finish() {
                $('.loading').hide();
                showMessage(fails ? 'fail' : 'success',
                    'Removed from ' + done + '/' + total + ' target(s)' +
                    (fails ? ' (' + fails + ' skipped/failed)' : '') + '.');
                setTimeout(function () { window.location.reload(); }, 700);
            }
        }
    });
})();
