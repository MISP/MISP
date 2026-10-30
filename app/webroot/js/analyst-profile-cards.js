/*
 * The profile index's enrichment line: fetch the enrichment card once the
 * page is up, sum it up on the line, keep it in the modal the line opens,
 * and run its one-click fixes in place.
 */
(function () {
    'use strict';

    var ICONS = {
        ok: 'circle-check',
        warn: 'triangle-exclamation',
        plain: 'circle-info'
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }

    function boot() {
        var line = document.querySelector('[data-ap-enrichment]');
        var modal = document.getElementById('ap-enrichment-modal');
        var body = modal ? modal.querySelector('[data-ap-card-src]') : null;
        if (!line || !body) {
            return;
        }
        var ctx = {
            line: line,
            modal: modal,
            body: body,
            src: body.getAttribute('data-ap-card-src')
        };
        load(ctx);
        body.addEventListener('click', function (event) {
            var button = event.target.closest('[data-ap-fix]');
            if (button && body.contains(button) && !button.disabled) {
                fix(ctx, button);
            }
        });
    }

    function load(ctx) {
        // A fresh URL each time, so no cached copy of the card comes back.
        var url = ctx.src + (ctx.src.indexOf('?') === -1 ? '?' : '&')
            + '_=' + Date.now();
        return fetch(url, {
            credentials: 'same-origin',
            headers: {'X-Requested-With': 'XMLHttpRequest'}
        }).then(function (response) {
            if (!response.ok) {
                throw new Error(String(response.status));
            }
            return response.text();
        }).then(function (html) {
            var holder = document.createElement('div');
            holder.innerHTML = html.trim();
            var card = holder.querySelector('.ap-card');
            if (!card) {
                throw new Error('empty');
            }
            ctx.body.replaceChildren(card);
            sumUp(ctx.line, card.getAttribute('data-ap-tone'),
                card.getAttribute('data-ap-summary'),
                card.getAttribute('data-ap-action'));
        }).catch(function () {
            var failed = document.createElement('p');
            failed.className = 'ap-card-line';
            failed.textContent = ctx.modal.getAttribute('data-ap-load-failed');
            ctx.body.replaceChildren(failed);
            sumUp(ctx.line, 'warn',
                ctx.modal.getAttribute('data-ap-unchecked'), null);
        });
    }

    function sumUp(line, tone, summary, action) {
        tone = ICONS[tone] ? tone : 'plain';
        line.setAttribute('data-tone', tone);
        var glyph = document.createElement('i');
        glyph.className = 'fas fa-' + ICONS[tone];
        line.querySelector('.ap-health-ico').replaceChildren(glyph);
        line.querySelector('[data-ap-summary]').textContent = summary || '';
        var open = line.querySelector('[data-ap-open]');
        open.textContent = action || '';
        open.hidden = !action;
    }

    function fix(ctx, button) {
        var kind = button.getAttribute('data-ap-fix');
        var body = new FormData();
        body.append('kind', kind);
        body.append('name', button.getAttribute('data-ap-name') || '');
        busy(button, true);
        fetch(ctx.modal.getAttribute('data-ap-fix-url'), {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Accept': 'application/json',
                'X-Requested-With': 'XMLHttpRequest',
                'X-CSRF-Token': token()
            },
            body: body
        }).then(function (response) {
            return response.json().catch(function () {
                return {};
            }).then(function (data) {
                return {ok: response.ok, data: data};
            });
        }).then(function (result) {
            var saved = result.ok && result.data.saved === true;
            toast(result.data.message
                || ctx.modal.getAttribute('data-ap-fix-failed'),
                saved ? 'success' : 'danger');
            if (!saved) {
                busy(button, false);
            } else if (kind === 'services') {
                window.location.reload();
            } else {
                load(ctx);
            }
        }).catch(function () {
            toast(ctx.modal.getAttribute('data-ap-fix-failed'), 'danger');
            busy(button, false);
        });
    }

    function busy(button, on) {
        button.disabled = on;
        button.setAttribute('aria-busy', on ? 'true' : 'false');
        var spinner = button.querySelector('.spinner-border');
        if (on && !spinner) {
            spinner = document.createElement('span');
            spinner.className = 'spinner-border spinner-border-sm me-1';
            spinner.setAttribute('aria-hidden', 'true');
            button.prepend(spinner);
        } else if (!on && spinner) {
            spinner.remove();
        }
    }

    function token() {
        if (typeof getCsrfToken === 'function') {
            return getCsrfToken();
        }
        return window.csrfToken || '';
    }

    function toast(message, variant) {
        if (typeof showToast === 'function') {
            showToast(message, variant);
        }
    }
})();
