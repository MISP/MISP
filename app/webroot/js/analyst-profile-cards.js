/*
 * The profile index's card row: fetch the enrichment card once the page is
 * up, and run its one-click fixes in place.
 */
(function () {
    'use strict';

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }

    function boot() {
        var row = document.querySelector('.ap-cards');
        var slot = row ? row.querySelector('[data-ap-card-src]') : null;
        if (!slot) {
            return;
        }
        var src = slot.getAttribute('data-ap-card-src');
        load(row, slot, src);
        row.addEventListener('click', function (event) {
            var button = event.target.closest('[data-ap-fix]');
            if (button && row.contains(button) && !button.disabled) {
                fix(row, button, src);
            }
        });
    }

    function load(row, card, src) {
        // A fresh URL each time, so no cached copy of the card comes back.
        var url = src + (src.indexOf('?') === -1 ? '?' : '&')
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
            var fresh = holder.querySelector('.ap-card');
            if (!fresh) {
                throw new Error('empty');
            }
            fresh.setAttribute('data-ap-card-src', src);
            card.replaceWith(fresh);
        }).catch(function () {
            card.removeAttribute('aria-busy');
            var wait = card.querySelector('.ap-card-wait');
            if (wait) {
                var line = document.createElement('p');
                line.className = 'ap-card-line';
                line.textContent = row.getAttribute('data-ap-load-failed');
                wait.replaceWith(line);
            }
        });
    }

    function fix(row, button, src) {
        var card = button.closest('.ap-card');
        var kind = button.getAttribute('data-ap-fix');
        var body = new FormData();
        body.append('kind', kind);
        body.append('name', button.getAttribute('data-ap-name') || '');
        busy(button, true);
        fetch(row.getAttribute('data-ap-fix-url'), {
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
            toast(result.data.message || row.getAttribute('data-ap-fix-failed'),
                saved ? 'success' : 'danger');
            if (!saved) {
                busy(button, false);
            } else if (kind === 'services') {
                window.location.reload();
            } else {
                load(row, card, src);
            }
        }).catch(function () {
            toast(row.getAttribute('data-ap-fix-failed'), 'danger');
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
