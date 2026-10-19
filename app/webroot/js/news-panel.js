// The news panel: the instance's news, over whatever page the user is on.
// A side panel (side-panel.js) opened by the navbar's News button or N. The
// news load on open, which marks them read on the server, so the button's
// unread count goes with them.
(function () {
    'use strict';

    var md = null;
    var mdLoading = null;
    var news = window.MispSidePanel && window.MispSidePanel.create('nw-so', {
        key: 'misp.news.panel',
        shortcut: 'n',
        beforeLoad: disposeTips,
        onLoad: function (body) {
            // The server marked the news read when it sent them.
            news.setCount(0);
            news.setLit(false);
            renderMarkdown(body);
        },
        onClose: disposeTips,
        forms: {
            match: /\/news\/(add|edit|deleteSelection)\b/,
            messages: {}
        }
    });
    if (!news) return;
    var panel = news.el;
    var body = news.body;
    var text = news.text;
    news.options.forms.messages = { add: text.added, edit: text.saved, deleteSelection: text.deleted };

    function loadOlder(button) {
        var page = parseInt(button.getAttribute('data-news-more'), 10) || 2;
        button.disabled = true;
        news.fetch(panel.getAttribute('data-url') + '/page:' + page).then(function (out) {
            var holder = document.createElement('div');
            holder.innerHTML = out;
            // The last day on screen may go on in this page.
            var days = body.querySelectorAll('[data-news-day]');
            var last = days.length ? days[days.length - 1].getAttribute('data-news-day') : null;
            var firstDay = holder.querySelector('[data-news-day]');
            if (firstDay && firstDay.getAttribute('data-news-day') === last) firstDay.remove();
            var first = holder.querySelector('.nw-msg');
            var frag = document.createDocumentFragment();
            while (holder.firstChild) frag.appendChild(holder.firstChild);
            button.replaceWith(frag);
            renderMarkdown(body);
            if (first) first.focus({ preventScroll: true });
        }).catch(function () {
            button.disabled = false;
            if (typeof showToast === 'function') showToast(text.olderFailed, 'danger');
        });
    }
    panel.addEventListener('click', function (e) {
        var more = e.target.closest('[data-news-more]');
        if (more) loadOlder(more);
    });

    // markdown-it is large and only the panel needs it, so it loads with the news.
    function markdownit() {
        if (window.markdownit) return Promise.resolve(window.markdownit);
        if (!mdLoading) {
            mdLoading = new Promise(function (resolve, reject) {
                var s = document.createElement('script');
                s.src = panel.getAttribute('data-markdown');
                s.onload = function () {
                    if (window.markdownit) resolve(window.markdownit); else reject(new Error('markdown-it'));
                };
                s.onerror = function () { mdLoading = null; reject(new Error('markdown-it')); };
                document.head.appendChild(s);
            });
        }
        return mdLoading;
    }
    function renderMarkdown(root) {
        if (!root.querySelector('[data-news-markdown]')) return;
        markdownit().then(function (factory) {
            if (!md) {
                md = factory('default');
                md.disable(['image']);
            }
            root.querySelectorAll('[data-news-markdown]').forEach(function (el) {
                el.innerHTML = md.render(el.textContent);
                el.removeAttribute('data-news-markdown');
            });
        }).catch(function () { /* the plain text stays */ });
    }

    // The exact date sits on the clock icon, as a tooltip made on first hover.
    function showTip(e) {
        var when = e.target.closest && e.target.closest('[data-news-when]');
        if (!when || !window.bootstrap) return;
        if (!window.bootstrap.Tooltip.getInstance(when)) {
            window.bootstrap.Tooltip.getOrCreateInstance(when, { placement: 'top', container: 'body' }).show();
        }
    }
    function disposeTips() {
        if (!window.bootstrap) return;
        document.querySelectorAll('#nw-so [data-news-when]').forEach(function (el) {
            var tip = window.bootstrap.Tooltip.getInstance(el);
            if (tip) tip.dispose();
        });
    }
    panel.addEventListener('mouseover', showTip);
    panel.addEventListener('focusin', showTip);

    window.NewsPanel = news;
}());
