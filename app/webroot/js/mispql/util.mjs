/*
 * MispQL console: small DOM and formatting helpers shared by its modules.
 */

function esc(s) {
    return String(s === null || s === undefined ? '' : s).replace(/[&<>"']/g, function (c) {
        return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
}

function el(tag, cls, html) {
    var e = document.createElement(tag);
    if (cls) {
        e.className = cls;
    }
    if (html !== undefined) {
        e.innerHTML = html;
    }
    return e;
}

function fmtInt(n) {
    return Number(n).toLocaleString('en-US');
}

function ago(seconds) {
    var d = Math.max(0, Math.floor(Date.now() / 1000) - seconds);
    if (d < 45) {
        return 'just now';
    }
    if (d < 3600) {
        return Math.round(d / 60) + ' min ago';
    }
    if (d < 86400) {
        return Math.round(d / 3600) + ' h ago';
    }
    if (d < 86400 * 2) {
        return 'yesterday';
    }
    return Math.round(d / 86400) + ' days ago';
}

function clock(seconds) {
    var d = new Date(seconds * 1000);
    return ('0' + d.getHours()).slice(-2) + ':' + ('0' + d.getMinutes()).slice(-2);
}

function bytes(n) {
    return n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(1) + ' MB';
}

/** text: a string, or a Blob kept as it came. */
function download(name, text, type) {
    var blob = text instanceof Blob ? text : new Blob([text], { type: type || 'text/plain' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    setTimeout(function () {
        URL.revokeObjectURL(a.href);
        a.remove();
    }, 500);
}

function jsonHTML(value) {
    var text = JSON.stringify(value, null, 2);
    return esc(text).replace(/(&quot;(?:[^&]|&(?!quot;))*?&quot;)(\s*:)?|\b(true|false|null)\b|(-?\b\d+(?:\.\d+)?\b)/g,
        function (m, str, colon, lit, num) {
            if (str) {
                return colon ? '<span class="js-key">' + str + '</span>' + colon : '<span class="js-str">' + str + '</span>';
            }
            if (lit) {
                return '<span class="js-lit">' + lit + '</span>';
            }
            return '<span class="js-num">' + num + '</span>';
        });
}

function copyText(text, button) {
    function done() {
        if (!button) {
            return;
        }
        var span = button.querySelector('span');
        var old = span ? span.textContent : '';
        button.classList.add('is-done');
        if (span) {
            span.textContent = 'Copied';
        }
        setTimeout(function () {
            button.classList.remove('is-done');
            if (span) {
                span.textContent = old;
            }
        }, 1400);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text); done(); });
    } else {
        fallbackCopy(text);
        done();
    }
}

function fallbackCopy(text) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try {
        document.execCommand('copy');
    } catch (e) { /* nothing more to try */ }
    ta.remove();
}

export {
    esc,
    el,
    fmtInt,
    ago,
    clock,
    bytes,
    download,
    jsonHTML,
    copyText,
};
