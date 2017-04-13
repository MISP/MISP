window.MISPUI = require("./misp-ui");

var functions = Object.keys(MISPUI);
for (var func in functions) {
    var funcName = functions[func];
    window[funcName] = MISPUI[funcName];
}
