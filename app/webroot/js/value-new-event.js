/*
 * The value page's new event: findings picked in the Enrichment tab collect
 * in a bar, and the dialog creates an event holding the value and them.
 * Picks are kept per value in the browser; the server reads the findings
 * themselves back from the organisation's stored answers.
 */
(function () {
    'use strict';

    function boot() {
        var bar = document.querySelector('[data-vp-ne-bar]');
        if (!bar) {
            return;
        }
        var d = bar.dataset;
        var storeKey = 'vp-ne-picks:' + d.key;
        var toasts = document.querySelector('.vp-ne-toasts');
        var picks = load();

        function load() {
            try {
                var raw = JSON.parse(localStorage.getItem(storeKey) || '[]');
                return Array.isArray(raw) ? raw.filter(function (p) {
                    return p && typeof p.fp === 'string' && typeof p.module === 'string' && typeof p.type === 'string';
                }) : [];
            } catch (e) {
                return [];
            }
        }

        function save() {
            try {
                if (picks.length) {
                    localStorage.setItem(storeKey, JSON.stringify(picks));
                } else {
                    localStorage.removeItem(storeKey);
                }
            } catch (e) { /* storage unavailable: picks last as long as the page */ }
            paint();
        }

        function indexOf(fp) {
            for (var i = 0; i < picks.length; i++) {
                if (picks[i].fp === fp) {
                    return i;
                }
            }
            return -1;
        }

        function fmt(str) {
            var args = Array.prototype.slice.call(arguments, 1);
            return String(str).replace(/%s/g, function () { return args.length ? String(args.shift()) : ''; });
        }

        function paintRow(row) {
            var on = indexOf(row.getAttribute('data-vp-ne-fp')) !== -1;
            row.classList.toggle('vp-ne-is-picked', on);
            var btn = row.querySelector('[data-vp-ne-pick]');
            if (!btn) {
                return;
            }
            btn.classList.toggle('btn-primary', on);
            btn.classList.toggle('btn-outline-primary', !on);
            btn.setAttribute('aria-pressed', on ? 'true' : 'false');
            var icon = btn.querySelector('i');
            if (icon) {
                icon.className = 'fas ' + (on ? 'fa-check' : 'fa-plus');
            }
            var label = btn.querySelector('[data-vp-ne-pick-label]');
            if (label) {
                label.textContent = on ? d.picked : d.pick;
            }
        }

        function enrichmentShown() {
            var pane = document.getElementById('tab-enrichment');
            return !!(pane && pane.classList.contains('active'));
        }

        function paint() {
            document.querySelectorAll('[data-vp-ne-fp]').forEach(paintRow);
            var modules = {};
            picks.forEach(function (p) { modules[p.module] = true; });
            var nModules = Object.keys(modules).length;
            bar.querySelector('[data-vp-ne-count]').textContent =
                fmt(picks.length === 1 ? d.findingsOne : d.findingsMany, picks.length) + ' '
                + fmt(nModules === 1 ? d.modulesOne : d.modulesMany, nModules);
            var on = picks.length > 0 && enrichmentShown();
            bar.classList.toggle('vp-ne-bar-on', on);
            document.body.classList.toggle('vp-ne-bar-shown', on);
        }

        var pending = null;
        new MutationObserver(function () {
            if (pending === null) {
                pending = window.requestAnimationFrame(function () {
                    pending = null;
                    paint();
                });
            }
        }).observe(document.body, { childList: true, subtree: true });
        document.addEventListener('shown.bs.tab', paint);
        var pane = document.getElementById('tab-enrichment');
        if (pane) {
            new MutationObserver(paint).observe(pane, { attributes: true, attributeFilter: ['class'] });
        }

        function openDialog() {
            var body = new FormData();
            body.append('data[_Token][key]', d.token);
            body.append('data[picks]', JSON.stringify(picks));
            openModalPostChained(d.url, body, 'xl');
        }

        document.addEventListener('click', function (e) {
            var pick = e.target.closest('[data-vp-ne-pick]');
            if (pick) {
                e.preventDefault();
                e.stopPropagation();
                var row = pick.closest('[data-vp-ne-fp]');
                if (!row) {
                    return;
                }
                var fp = row.getAttribute('data-vp-ne-fp');
                var at = indexOf(fp);
                if (at === -1) {
                    picks.push({ fp: fp, module: row.getAttribute('data-vp-ne-module'), type: row.getAttribute('data-vp-ne-type') });
                } else {
                    picks.splice(at, 1);
                }
                save();
                return;
            }
            if (e.target.closest('[data-vp-ne-open]')) {
                e.preventDefault();
                openDialog();
                return;
            }
            if (e.target.closest('[data-vp-ne-clear]')) {
                picks = [];
                save();
                return;
            }
            var rm = e.target.closest('[data-vp-ne-rm]');
            if (rm) {
                removeFinding(rm);
            }
        });

        function removeFinding(rm) {
            var form = rm.closest('[data-vp-ne-form]');
            var fp = rm.getAttribute('data-vp-ne-rm');
            var group = rm.closest('[data-vp-ne-group]');
            rm.closest('[data-vp-ne-row]').remove();
            if (group && !group.querySelector('[data-vp-ne-row]')) {
                group.remove();
            }
            var left = form.querySelectorAll('[data-vp-ne-row]').length;
            var badge = form.querySelector('[data-vp-ne-findings] .badge');
            if (badge) {
                badge.textContent = left;
                badge.classList.toggle('d-none', left === 0);
            }
            form.querySelector('[data-vp-ne-empty]').classList.toggle('d-none', left > 0);
            var at = indexOf(fp);
            if (at !== -1) {
                picks.splice(at, 1);
                save();
            }
        }

        function typeInfo(form) {
            var el = form.querySelector('[data-vp-ne-types]');
            try {
                return el ? JSON.parse(el.textContent) : {};
            } catch (err) {
                return {};
            }
        }

        document.addEventListener('change', function (e) {
            var select = e.target.closest('[data-vp-ne-type-for]');
            if (!select) {
                return;
            }
            var form = select.closest('[data-vp-ne-form]');
            var info = typeInfo(form)[select.value];
            var target = form.querySelector(select.getAttribute('data-vp-ne-type-for'));
            if (!info || !target) {
                return;
            }
            var keep = target.value;
            target.innerHTML = '';
            info.categories.forEach(function (category) {
                var option = document.createElement('option');
                option.value = category;
                option.textContent = category;
                target.appendChild(option);
            });
            target.value = info.categories.indexOf(keep) !== -1 ? keep : info.categories[0];
            var ids = form.querySelector('[data-vp-ne-ids-for="#' + select.id + '"]');
            if (ids) {
                ids.checked = !!info.to_ids;
            }
        });

        document.addEventListener('submit', function (e) {
            var form = e.target.closest('[data-vp-ne-form]');
            if (!form || e.defaultPrevented) {
                return;
            }
            e.preventDefault();
            var submit = form.querySelector('[type="submit"]');
            var error = form.querySelector('[data-vp-ne-error]');
            error.classList.add('d-none');
            if (submit) {
                submit.disabled = true;
            }
            fetch(form.getAttribute('action'), {
                method: 'POST',
                body: new FormData(form),
                credentials: 'same-origin',
                headers: { 'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json' }
            }).then(function (response) {
                return response.json().catch(function () { return {}; }).then(function (json) {
                    return { ok: response.ok, json: json };
                });
            }).then(function (r) {
                if (!r.ok || !r.json.event_id) {
                    var errors = r.json.errors ? Object.keys(r.json.errors).map(function (k) { return r.json.errors[k]; }) : [d.error];
                    error.textContent = errors.join(' ');
                    error.classList.remove('d-none');
                    error.scrollIntoView({ block: 'nearest' });
                    if (submit) {
                        submit.disabled = false;
                    }
                    return;
                }
                var sent = Array.prototype.map.call(form.querySelectorAll('[data-vp-ne-row]'), function (row) {
                    return row.getAttribute('data-vp-ne-row');
                });
                picks = picks.filter(function (p) { return sent.indexOf(p.fp) === -1; });
                save();
                var modal = bootstrap.Modal.getInstance(document.getElementById('mainModal'));
                if (modal) {
                    modal.hide();
                }
                created(r.json);
            }).catch(function () {
                error.textContent = d.error;
                error.classList.remove('d-none');
                if (submit) {
                    submit.disabled = false;
                }
            });
        });

        function created(result) {
            var n = result.saved + result.existing;
            var text = n === 0 ? fmt(d.created, result.event_id)
                : n === 1 ? fmt(d.createdOne, result.event_id)
                    : fmt(d.createdMany, result.event_id, n);
            var toast = document.createElement('div');
            toast.className = 'toast vp-ne-toast';
            toast.setAttribute('role', 'status');
            toast.innerHTML = '<div class="vp-ne-toast-body">'
                + '<i class="fas fa-circle-check vp-ne-toast-ok" aria-hidden="true"></i>'
                + '<div class="vp-ne-toast-text"><div data-text></div><div class="vp-ne-toast-warn" data-warn></div>'
                + '<a class="vp-ne-toast-link" data-link><span data-open></span> <i class="fas fa-arrow-right" aria-hidden="true"></i></a></div>'
                + '<button type="button" class="btn-close" data-bs-dismiss="toast"></button></div>';
            toast.querySelector('[data-text]').textContent = text;
            var warn = toast.querySelector('[data-warn]');
            if (result.failed > 0) {
                warn.textContent = fmt(d.failed, result.failed);
            } else {
                warn.remove();
            }
            toast.querySelector('[data-link]').href = result.url;
            toast.querySelector('[data-open]').textContent = d.open;
            toast.querySelector('.btn-close').setAttribute('aria-label', d.close);
            toasts.appendChild(toast);
            toast.addEventListener('hidden.bs.toast', function () { toast.remove(); });
            bootstrap.Toast.getOrCreateInstance(toast, { delay: 9000 }).show();
        }

        paint();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }
})();
