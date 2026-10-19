// The bookmarks panel: the user's bookmarks and the ones their organisation
// shares, over whatever page the user is on. A side panel (side-panel.js)
// opened by the navbar's Bookmarks button or B.
(function () {
    'use strict';

    var bookmarks = window.MispSidePanel && window.MispSidePanel.create('bm-so', {
        key: 'misp.bookmarks.panel',
        shortcut: 'b',
        focus: '[data-bm-filter]',
        onLoad: function (body) {
            markHere(body);
            applyFilter();
        },
        forms: {
            match: /\/bookmarks\/(add|edit|deleteSelection)\b/,
            messages: {}
        }
    });
    if (!bookmarks) return;
    var panel = bookmarks.el;
    var body = bookmarks.body;
    var text = bookmarks.text;
    var filter = panel.querySelector('[data-bm-filter]');
    var filterBox = panel.querySelector('[data-bm-filter-box]');
    var countEl = panel.querySelector('[data-bm-count]');
    bookmarks.options.forms.messages = { add: text.added, edit: text.saved, deleteSelection: text.deleted };

    // The add form, named after the page underneath and pointed at it.
    panel.querySelector('[data-bm-add]').addEventListener('click', function () {
        var query = new URLSearchParams({
            url: location.href.split('#')[0],
            name: document.title.replace(/\s+-\s+[^-]*$/, '')
        });
        bookmarks.openModal(panel.getAttribute('data-add') + '?' + query.toString(), 'lg');
    });

    function markHere(root) {
        var here = location.pathname + location.search;
        root.querySelectorAll('a[data-bm-href]').forEach(function (a) {
            var url;
            try { url = new URL(a.href); } catch (e) { return; }
            var on = url.origin === location.origin && url.pathname + url.search === here;
            a.closest('.bm-item').classList.toggle('is-here', on);
            if (on) a.setAttribute('aria-current', 'page');
        });
    }

    function applyFilter() {
        var items = body.querySelectorAll('.bm-item');
        var q = filter.value.trim().toLowerCase();
        filterBox.hidden = items.length === 0 && !q;
        var shown = 0;
        items.forEach(function (item) {
            var hit = !q || item.getAttribute('data-bm-text').indexOf(q) !== -1;
            item.hidden = !hit;
            if (hit) shown++;
        });
        body.querySelectorAll('.bm-section').forEach(function (section) {
            section.hidden = !section.querySelector('.bm-item:not([hidden])');
        });
        var none = body.querySelector('[data-bm-nomatch]');
        if (none) none.hidden = !(q && !shown);
        countEl.hidden = !q;
        countEl.textContent = shown + ' / ' + items.length;
    }
    filter.addEventListener('input', applyFilter);
    filter.addEventListener('keydown', function (e) {
        if (e.key !== 'Escape' || !filter.value) return;
        e.stopPropagation();
        filter.value = '';
        applyFilter();
    });

    window.BookmarksPanel = bookmarks;
}());
