Java.perform(function() {
    const System = Java.use('java.lang.System');
    const Runtime = Java.use('java.lang.Runtime');
    const VMStack = Java.use('dalvik.system.VMStack');
    var mfl = []; //modelfdlist=[];
    //var bml = []; // big malloc list;
    var bml = {}; // big malloc list;
    var fml = []; // already freed list;
    var flag_malloc_hooked = false;
    var count = 1;
    //var libnamedic = require("./liballdic.json");
    //var libnamedic = require("./libfwdic.json");
    //var libnamedic = require("./libmagicdic.json");
    var libnamedic = 
