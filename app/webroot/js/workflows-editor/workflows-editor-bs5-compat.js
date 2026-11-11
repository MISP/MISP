/*
 * Bootstrap 2 -> Bootstrap 5 compatibility layer for the workflow editor.
 *
 * workflows-editor.js is deliberately left untouched by the Overmind migration:
 * it is 2700 lines of drawflow/jQuery-UI logic whose behaviour would be very
 * hard to preserve through a rewrite. Instead the editor page keeps jQuery and
 * this file re-implements, on top of Bootstrap 5, the handful of Bootstrap 2
 * jQuery plugin APIs the editor calls:
 *
 *   $el.modal('show'|'hide')          $el.on('show'|'shown', fn)
 *   $el.tab('show')                   [data-toggle="modal"] delegated opener
 *   $el.popover(opts|'show')          $el.data('popover').tip()
 *   openGenericModal(url, size, cb)   (misp.js helper, absent from mispOvermind)
 *
 */
(function ($) {
    'use strict';

    if (!$) {
        return;
    }

    /*
     * Bootstrap 5 registers its own jQuery plugins ($.fn.modal, $.fn.tab,
     * $.fn.popover, …) from a DOMContentLoaded callback whenever window.jQuery
     * exists. bootstrap.bundle.min.js is loaded by the layout at the end of the
     * body — after this file — so its listener runs after ours and would
     * silently overwrite the shims below.
     *
     * Symptom when that happens: the node settings modal opens (Bootstrap 5's
     * own implementation) but stays empty, because the editor populates it from
     * a Bootstrap 2 `show` event that nothing re-emits.
     *
     * So install the shims eagerly *and* re-assert them on `load`, which fires
     * after every DOMContentLoaded callback. Every interaction that relies on
     * them is user-driven, hence necessarily post-load.
     */
    function installShims() {
        $.fn.modal = shimModal;
        $.fn.tab = shimTab;
        $.fn.popover = shimPopover;
    }

    /* ---------------------------------------------------------------- modal */

    /*
     * Bootstrap 2 fired `show`/`shown`; Bootstrap 5 fires `show.bs.modal` /
     * `shown.bs.modal`. The editor listens for the short names, so mirror them.
     *
     * Bound eagerly on every modal rather than lazily from $.fn.modal: the
     * bridge has to work no matter which implementation ends up opening the
     * dialog.
     */
    function bridgeModalEvents(el) {
        if (el._bs2EventsBridged) {
            return;
        }
        el._bs2EventsBridged = true;
        [['show.bs.modal', 'show'], ['shown.bs.modal', 'shown'],
         ['hide.bs.modal', 'hide'], ['hidden.bs.modal', 'hidden']].forEach(function (pair) {
            el.addEventListener(pair[0], function () {
                $(el).trigger(pair[1]);
            });
        });
    }

    function shimModal(action) {
        return this.each(function () {
            bridgeModalEvents(this);
            var instance = bootstrap.Modal.getOrCreateInstance(this);
            if (action === 'hide') {
                instance.hide();
            } else if (action === 'toggle') {
                instance.toggle();
            } else {
                // Bootstrap 2 treated both `show` and an options object as "open".
                instance.show();
            }
        });
    }

    /*
     * The node templates in workflows-editor.js render
     * `<a href="#block-modal" data-toggle="modal">`, which Bootstrap 5 ignores
     * (it looks for data-bs-toggle / data-bs-target). Delegate it here so the
     * generated markup keeps working verbatim.
     */
    document.addEventListener('click', function (evt) {
        var trigger = evt.target.closest('[data-toggle="modal"]');
        if (!trigger) {
            return;
        }
        var selector = trigger.getAttribute('data-target') || trigger.getAttribute('href');
        if (!selector || selector.charAt(0) !== '#') {
            return;
        }
        var target = document.querySelector(selector);
        if (!target) {
            return;
        }
        evt.preventDefault();
        $(target).modal('show');
    });

    /* ------------------------------------------------------------------ tab */

    function shimTab(action) {
        return this.each(function () {
            if (action === 'show') {
                bootstrap.Tab.getOrCreateInstance(this).show();
            }
        });
    }

    /* -------------------------------------------------------------- popover */

    /*
     * The "Run workflow" button drives its popover through the Bootstrap 2 API:
     * it probes `.data().popover` to avoid double-initialising, then reaches the
     * rendered tip via `.data('popover').tip()`. Bootstrap 5 exposes the tip as
     * `instance.tip`, so wrap it in the shape the editor expects.
     *
     * The Bootstrap 2 `template` option is dropped on purpose: its class names
     * (.popover-title / .popover-content / .arrow) no longer exist in Bootstrap
     * 5. The default template carries the content in `.popover-body`, and the
     * editor only ever does `$popover.find('button'|'textarea'|'input')`, so the
     * lookups still resolve.
     */
    function shimPopover(arg) {
        return this.each(function () {
            var $el = $(this);
            var stored = $el.data('popover');

            if (typeof arg === 'string') {
                if (stored && stored._instance) {
                    stored._instance[arg]();
                }
                return;
            }

            var options = arg || {};
            var instance = new bootstrap.Popover(this, {
                html: options.html !== undefined ? options.html : false,
                placement: options.placement || 'right',
                trigger: options.trigger || 'click',
                content: options.content || '',
                title: options.title || '',
                container: options.container || false,
                sanitize: false
            });
            $el.data('popover', {
                _instance: instance,
                tip: function () {
                    return $(instance.tip);
                }
            });
        });
    }

    /* ------------------------------------------------------------ install */

    function bridgeAllModals() {
        document.querySelectorAll('.modal').forEach(bridgeModalEvents);
    }

    installShims();
    document.addEventListener('DOMContentLoaded', bridgeAllModals);
    window.addEventListener('load', function () {
        installShims();
        bridgeAllModals();
    });

    /* --------------------------------------------------- openGenericModal */

    /*
     * misp.js helper used by the editor's "Save blueprint" flow. mispOvermind.js
     * has openModal(), but the editor's callback reaches into `#genericModal`
     * for the loaded form, so keep that contract: load the fragment into the
     * shared Overmind modal, wrapped in an element carrying the expected id.
     */
    if (typeof window.openGenericModal !== 'function') {
        window.openGenericModal = function (url, size, callback) {
            var modalEl = document.getElementById('mainModal');
            var modalBody = document.getElementById('mainModalBody');
            if (!modalEl || !modalBody) {
                return;
            }
            var dialog = modalEl.querySelector('.modal-dialog');
            dialog.classList.remove('modal-sm', 'modal-lg', 'modal-xl');
            dialog.classList.add('modal-' + (size || 'xl'));

            fetch(url, { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
                .then(function (response) {
                    if (!response.ok) {
                        throw new Error('HTTP ' + response.status);
                    }
                    return response.text();
                })
                .then(function (html) {
                    modalBody.innerHTML = '<div id="genericModal">' + html + '</div>';
                    // Re-run any script the fragment brought with it.
                    modalBody.querySelectorAll('script').forEach(function (old) {
                        var script = document.createElement('script');
                        if (old.src) {
                            script.src = old.src;
                        } else {
                            script.textContent = old.textContent;
                        }
                        document.head.appendChild(script);
                        document.head.removeChild(script);
                    });
                    bootstrap.Modal.getOrCreateInstance(modalEl).show();
                    if (typeof callback === 'function') {
                        callback();
                    }
                })
                .catch(function () {
                    if (typeof showMessage === 'function') {
                        showMessage('fail', 'Could not load the requested form.');
                    }
                });
        };
    }
})(window.jQuery);
