/* The reader's grade of an organisation: the badge on the org's mark opens a
   menu that writes the grade into the reader's own analyst profile
   (POST /analystProfiles/grade/<org id>). Markup: OrgGradeHelper. */
(function () {
    'use strict';

    // The events index brings this script again with every reload.
    if (window.mispOrgGrade) return;
    window.mispOrgGrade = true;

    var LETTERS = ['A', 'B', 'C', 'D', 'E', 'F', 'G'];
    var GROUPS = [
        { tone: 'more', label: 'Counts more' },
        { tone: 'neutral', label: 'Counts as usual' },
        { tone: 'less', label: 'Counts less' },
        { tone: 'void', label: 'Disregarded' }
    ];
    var DESC = {
        F: 'You can’t say. Weighs like no opinion.',
        G: 'An accusation: their reports stop counting.'
    };
    var VIA = {
        instance: 'the instance default',
        user_selection: 'the profile you selected',
        org: 'your organisation’s profile',
        org_selection: 'the profile your organisation selected',
        user: 'your own profile'
    };

    var C = null;
    var configNode = null;
    var picker = { el: null, trigger: null, org: null, grade: '', busy: false, changed: null };

    function config() {
        var node = document.getElementById('og-config');
        if (node && node !== configNode) {
            try {
                C = JSON.parse(node.textContent);
                configNode = node;
            } catch (e) {
                return C;
            }
        }
        return C;
    }

    function tone(g) {
        var s = C.scale[g];
        if (s > 1) return 'more';
        if (s === 1) return 'neutral';
        if (s > 0) return 'less';
        return 'void';
    }
    function factor(g) {
        var s = C.scale[g];
        return '×' + (s === 0 ? '0' : Number(s).toFixed(2));
    }
    function esc(s) {
        return String(s).replace(/[&<>"']/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
    }
    function chip(g) {
        if (!g) return '<span class="og-chip og-chip-clear" aria-hidden="true"><i class="fas fa-ban"></i></span>';
        return '<span class="og-chip og-tone-' + tone(g) + '" aria-hidden="true">' + g + '</span>';
    }
    function gradeWords(g) {
        return g ? g + ', ' + C.labels[g] : C.labels.unrated;
    }
    function orgOf(badge) {
        return {
            id: badge.getAttribute('data-org-id'),
            uuid: badge.getAttribute('data-grade-for'),
            name: badge.getAttribute('data-org-name')
        };
    }
    function badgesFor(uuid) {
        return Array.prototype.slice.call(document.querySelectorAll('.og-badge[data-grade-for="' + uuid + '"]'));
    }

    function paint(b, g) {
        var org = orgOf(b);
        var variant = ['is-large', 'is-square'].filter(function (c) { return b.classList.contains(c); });
        b.setAttribute('data-grade', g);
        b.className = ['og-badge'].concat(variant, g ? 'og-tone-' + tone(g) : 'is-empty').join(' ');
        b.innerHTML = g ? g : '<i class="fas fa-plus" aria-hidden="true"></i>';
        var via = C.target.mode === 'fork' && g ? ' (from ' + C.target.profile.name + ')' : '';
        var label = g ? 'Graded ' + gradeWords(g) + via + '. Change the grade' : 'Grade ' + org.name;
        b.title = label;
        b.setAttribute('aria-label', org.name + ': ' + label);
    }

    /* the menu */

    function build() {
        var el = document.createElement('div');
        el.className = 'dropdown-menu show og-menu';
        el.setAttribute('data-grade-picker', '');
        el.setAttribute('role', 'dialog');
        el.hidden = true;
        el.addEventListener('click', onClick);
        document.body.appendChild(el);
        picker.el = el;
    }

    function whereNote(org) {
        var t = C.target;
        var name = '<strong>' + esc(t.profile.name) + '</strong>';
        if (t.mode === 'own') return 'Saved in your profile ' + name + '.';
        var via = esc(VIA[t.profile.via] || 'a shared profile');
        if (picker.grade) {
            return 'The grade shown comes from ' + name + ', ' + via + '. A grade you pick goes into your own copy of it.';
        }
        return 'Your first grade makes your own copy of ' + name + ', ' + via + '.';
    }

    function listPane(org) {
        var cur = picker.grade;
        var h = '<div class="og-pane" data-pane="list">' +
            '<div class="og-head"><span class="og-head-text">' +
            '<span class="og-head-title">How reliable is ' + esc(org.name) + '?</span>' +
            '<span class="og-head-sub">Sets how much its reports and sightings count.</span>' +
            '</span></div><div class="og-divider"></div><div role="menu" aria-label="Grades">';
        GROUPS.forEach(function (grp) {
            var letters = LETTERS.filter(function (g) { return tone(g) === grp.tone; });
            if (!letters.length) return;
            h += '<div class="og-group" aria-hidden="true">' + grp.label + '</div>';
            letters.forEach(function (g) {
                var on = g === cur;
                h += '<button type="button" class="dropdown-item og-item' + (on ? ' is-on' : '') + '" role="menuitemradio"' +
                    ' aria-checked="' + on + '" data-grade-option="' + g + '"' +
                    ' title="' + esc(org.name) + '’s reports and sightings count ' + factor(g) + '">' +
                    '<i class="og-tick fas fa-check" aria-hidden="true"></i>' + chip(g) +
                    '<span class="og-text"><span class="og-label">' + esc(C.labels[g]) + '</span>' +
                    (DESC[g] ? '<span class="og-desc">' + esc(DESC[g]) + '</span>' : '') +
                    '</span><span class="og-x">' + factor(g) + '</span></button>';
            });
        });
        h += '<div class="og-divider"></div>' +
            '<button type="button" class="dropdown-item og-item' + (cur ? '' : ' is-on') + '" role="menuitemradio"' +
            ' aria-checked="' + !cur + '" data-grade-option="unrated">' +
            '<i class="og-tick fas fa-check" aria-hidden="true"></i>' + chip('') +
            '<span class="og-text"><span class="og-label">' + esc(C.labels.unrated) + '</span>' +
            (cur ? '<span class="og-desc">Removes your grade.</span>' : '') +
            '</span></button></div>' +
            '<div class="og-error" role="alert" hidden></div>' +
            '<div class="og-note">' + whereNote(org) + '</div></div>';
        return h;
    }

    function confirmPane(org, letter) {
        var t = C.target.profile;
        var g = letter === 'unrated' ? '' : letter;
        var name = '<strong>' + esc(t.name) + '</strong>';
        return '<div class="og-pane is-entering" data-pane="confirm" role="group" aria-label="Make your own copy">' +
            '<div class="og-head"><button type="button" class="og-back" data-og-back aria-label="Back to the grades">' +
            '<i class="fas fa-chevron-left" aria-hidden="true"></i></button>' +
            '<span class="og-head-text"><span class="og-head-title">This makes your own copy</span></span></div>' +
            '<div class="og-divider"></div><div class="og-body">' +
            '<div class="og-choice">' + chip(g) + '<span><strong>' + esc(g ? C.labels[g] : C.labels.unrated) +
            '</strong> for ' + esc(org.name) + '</span></div>' +
            '<p>' + (g ? 'Grading' : 'Removing the grade') + ' makes your own copy of ' + name + ', ' +
            esc(VIA[t.via] || 'a shared profile') + '. The copy becomes the profile in force for you.</p>' +
            '<p>Later changes to ' + name + ' will stop reaching you.</p>' +
            '<p class="og-quiet">The copy keeps every weight, grade and pin it has now, so nothing else on your pages changes.</p>' +
            '<div class="og-actions">' +
            '<button type="button" class="btn btn-sm btn-primary" data-grade-confirm-fork data-letter="' + letter + '">' +
            '<i class="fas fa-code-fork" aria-hidden="true"></i><span>' +
            (g ? 'Make my copy and grade ' + g : 'Make my copy and remove it') + '</span></button>' +
            '<button type="button" class="btn btn-sm btn-outline-secondary" data-og-cancel>Cancel</button>' +
            '</div></div><div class="og-error" role="alert" hidden></div></div>';
    }

    function donePane(org, body) {
        var g = body.grade || '';
        return '<div class="og-pane is-entering" data-pane="done" role="status">' +
            '<div class="og-head"><i class="fas fa-circle-check og-done-icon" aria-hidden="true"></i>' +
            '<span class="og-head-text"><span class="og-head-title">' +
            (g ? esc(org.name) + ' graded ' + g : 'Grade removed for ' + esc(org.name)) +
            '</span></span></div><div class="og-divider"></div><div class="og-body">' +
            '<p>Your copy, <strong>' + esc(body.profile.name) + '</strong>, is now the profile in force for you. ' +
            'Your grades go there from now on.</p>' +
            '<div class="og-actions"><button type="button" class="btn btn-sm btn-primary" data-og-done>Done</button></div>' +
            '</div></div>';
    }

    function show(html) {
        picker.el.innerHTML = html;
        place();
        var pane = picker.el.querySelector('.og-pane');
        setTimeout(function () { if (pane) pane.classList.remove('is-entering', 'is-returning'); }, 200);
    }

    function open(trigger) {
        if (picker.trigger) close(false);
        if (!picker.el) build();
        picker.trigger = trigger;
        picker.org = orgOf(trigger);
        picker.grade = trigger.getAttribute('data-grade') || '';
        picker.el.setAttribute('aria-label', 'Grade ' + picker.org.name);
        trigger.setAttribute('aria-expanded', 'true');
        picker.el.hidden = false;
        show(listPane(picker.org));
        focusFirst();
    }

    function close(returnFocus) {
        if (!picker.trigger || picker.busy) return;
        var t = picker.trigger;
        picker.el.hidden = true;
        picker.el.innerHTML = '';
        picker.el.classList.remove('is-busy', 'is-above');
        t.setAttribute('aria-expanded', 'false');
        picker.trigger = null;
        picker.org = null;
        if (returnFocus) t.focus();
        if (picker.changed) {
            var detail = picker.changed;
            picker.changed = null;
            document.dispatchEvent(new CustomEvent('og:graded', { detail: detail }));
        }
    }

    function place() {
        var el = picker.el, t = picker.trigger;
        if (!el || !t) return;
        var r = (t.parentElement || t).getBoundingClientRect();
        var w = el.offsetWidth, h = el.offsetHeight;
        var vw = document.documentElement.clientWidth, vh = window.innerHeight;
        var top0 = 64, gap = 8, sx = window.scrollX, sy = window.scrollY;
        var left = Math.max(8, Math.min(r.left - 4, vw - w - 8));
        var top, above = false;
        if (r.bottom + gap + h <= vh - 8) {
            top = r.bottom + gap;
        } else if (r.top - gap - h >= top0) {
            top = r.top - gap - h;
            above = true;
        } else {
            top = Math.max(top0, Math.min(r.top - 12, vh - h - 8));
            left = r.right + 12 + w <= vw - 8 ? r.right + 12 : Math.max(8, r.left - 12 - w);
        }
        el.classList.toggle('is-above', above);
        el.style.left = (left + sx) + 'px';
        el.style.top = (top + sy) + 'px';
    }

    function focusables() {
        var pane = picker.el && picker.el.querySelector('.og-pane');
        return pane ? Array.prototype.slice.call(pane.querySelectorAll('button:not([disabled])')) : [];
    }
    function focusFirst() {
        var f = picker.el.querySelector('.og-item.is-on') || focusables()[0];
        if (f) f.focus({ preventScroll: true });
    }

    function onKey(e) {
        if (e.key === 'Escape') {
            e.preventDefault();
            close(true);
            return;
        }
        if (e.key === 'Tab') { close(true); return; }
        var list = focusables();
        var i = list.indexOf(document.activeElement);
        var next = null;
        if (e.key === 'ArrowDown') next = list[(i + 1) % list.length];
        else if (e.key === 'ArrowUp') next = list[(i - 1 + list.length) % list.length];
        else if (e.key === 'Home') next = list[0];
        else if (e.key === 'End') next = list[list.length - 1];
        if (next) { e.preventDefault(); next.focus(); }
    }

    function onClick(e) {
        var opt = e.target.closest('[data-grade-option]');
        if (opt) { choose(opt.getAttribute('data-grade-option'), opt); return; }
        var fork = e.target.closest('[data-grade-confirm-fork]');
        if (fork) { save(fork.getAttribute('data-letter'), true, fork); return; }
        if (e.target.closest('[data-og-back]')) {
            show(listPane(picker.org).replace('class="og-pane"', 'class="og-pane is-returning"'));
            focusFirst();
            return;
        }
        if (e.target.closest('[data-og-cancel]') || e.target.closest('[data-og-done]')) close(true);
    }

    function choose(letter, item) {
        if (picker.busy) return;
        var want = letter === 'unrated' ? null : letter;
        if (want === (picker.grade || null)) { close(true); return; }
        if (C.target.mode === 'fork') {
            show(confirmPane(picker.org, letter));
            var go = picker.el.querySelector('[data-grade-confirm-fork]');
            if (go) go.focus({ preventScroll: true });
            return;
        }
        save(letter, false, item);
    }

    function setBusy(on, control) {
        picker.busy = on;
        picker.el.classList.toggle('is-busy', on);
        picker.el.setAttribute('aria-busy', on ? 'true' : 'false');
        badgesFor(picker.org.uuid).forEach(function (b) { b.classList.toggle('is-saving', on); });
        if (!control) return;
        if (control.classList.contains('og-item')) {
            control.classList.toggle('is-pending', on);
            control.querySelector('.og-tick').className = on ? 'og-tick fas fa-circle-notch fa-spin' : 'og-tick fas fa-check';
        } else {
            control.disabled = on;
            var icon = control.querySelector('i');
            if (icon) icon.className = on ? 'fas fa-circle-notch fa-spin' : 'fas fa-code-fork';
        }
    }

    function showError(body) {
        var box = picker.el.querySelector('.og-pane .og-error');
        if (!box) return;
        var org = picker.org;
        var cur = picker.grade;
        var why = (body && body.errors && body.errors[0]) || (body && (body.message || body.name)) ||
            'The grade could not be saved.';
        box.innerHTML = '<i class="fas fa-circle-exclamation" aria-hidden="true"></i><span>' + esc(why) + ' ' +
            esc(org.name) + (cur ? ' is still graded ' + cur + '.' : ' is still not graded.') + '</span>';
        box.hidden = false;
        place();
    }

    function post(org, letter, fork) {
        var body = 'grade=' + encodeURIComponent(letter) + (fork ? '&fork=1' : '');
        return fetch(C.url + encodeURIComponent(org.id), {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-Requested-With': 'XMLHttpRequest',
                'X-CSRF-Token': window.csrfToken || ''
            },
            body: body
        }).then(function (res) {
            return res.json().catch(function () { return null; }).then(function (json) {
                return { status: res.status, body: json };
            });
        }, function () {
            return { status: 0, body: { message: 'The grade could not be sent.' } };
        });
    }

    function save(letter, fork, control) {
        var org = picker.org;
        setBusy(true, control);
        post(org, letter, fork).then(function (res) {
            if (picker.org !== org) return;
            setBusy(false, control);
            if (res.status === 409 && res.body && res.body.needs_fork) {
                show(confirmPane(org, letter));
                var go = picker.el.querySelector('[data-grade-confirm-fork]');
                if (go) go.focus({ preventScroll: true });
                return;
            }
            if (res.status !== 200 || !res.body) { showError(res.body); return; }
            picker.grade = res.body.grade || '';
            picker.changed = { uuid: org.uuid, grade: res.body.grade || null };
            if (res.body.forked) {
                C.target = { mode: 'own', profile: { id: res.body.profile.id, name: res.body.profile.name, via: 'user' } };
            }
            badgesFor(org.uuid).forEach(function (b) {
                paint(b, picker.grade);
                b.classList.remove('is-fresh');
                void b.offsetWidth;
                if (res.body.grade) b.classList.add('is-fresh');
            });
            if (res.body.forked) {
                document.querySelectorAll('.og-badge').forEach(function (b) {
                    paint(b, b.getAttribute('data-grade') || '');
                });
                show(donePane(org, res.body));
                var done = picker.el.querySelector('[data-og-done]');
                if (done) done.focus({ preventScroll: true });
            } else {
                close(true);
            }
        });
    }

    function init() {
        document.addEventListener('click', function (e) {
            var b = e.target.closest('.og-badge');
            if (b && config()) {
                e.preventDefault();
                e.stopPropagation();
                if (picker.trigger === b) close(true); else open(b);
                return;
            }
            if (picker.trigger && e.target.closest('#viewList, #viewCard')) close(false);
        }, true);
        document.addEventListener('dblclick', function (e) {
            if (e.target.closest('.og-badge, .og-menu')) e.stopPropagation();
        }, true);
        // Bootstrap's dropdown handler swallows keys inside any .dropdown-menu
        window.addEventListener('keydown', function (e) {
            if (picker.el && picker.trigger && picker.el.contains(e.target)) {
                e.stopPropagation();
                onKey(e);
            }
        }, true);
        document.addEventListener('mousedown', function (e) {
            if (!picker.trigger || picker.busy) return;
            if (picker.el.contains(e.target) || picker.trigger.contains(e.target)) return;
            close(false);
        });
        window.addEventListener('resize', function () { if (picker.trigger) place(); });
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
})();
