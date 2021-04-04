Java.perform(function() {
    const System = Java.use('java.lang.System');
    const Runtime = Java.use('java.lang.Runtime');
    const VMStack = Java.use('dalvik.system.VMStack');
    var mfl = []; //modelfdlist=[];
    //var libnamedic = require("./liballdic.json");
    //var libnamedic = require("./libfwdic.json");
    //var libnamedic = require("./libmagicdic.json");
    var libnamedic = {"libname":["func1","func2"],"libname2":["func1","func2"]};
    //hookopen();
    //hookmmap();
    System.loadLibrary.implementation = function(library) {
        try {
            console.log('System.loadLibrary("' + library + '")');
            const loaded = Runtime.getRuntime().loadLibrary0(VMStack.getCallingClassLoader(), library);
		    //var libnamedic = {"libname":["func1","func2"],};
            for (var libname in libnamedic) {
	            if (library === libname){
		            console.log("after loading " + libname + " let's do hook");
       	        	hooknative(libname, libnamedic[libname]);
	            };
            }
            return loaded;
        } catch(ex) {
            console.log(ex);
        }
    };
    
    System.load.implementation = function(library) {
        try {
            console.log('System.load("' + library + '")');
            const loaded = Runtime.getRuntime().load0(VMStack.getCallingClassLoader(), library);
		    var libnamedic = {"libname":["func1","func2"],};
            for (libname in libnamedic) {
	            if (library === libname){
		            console.log("after loading " + libname + " let's do hook");
       	        	hooknative(libname, libnamedic[libname]);
	            };
            }
            return loaded;
        } catch(ex) {
            console.log(ex);
        }
    };

    function bufferToHex(buffer) { // buffer is an ArrayBuffer
        var res = "";
        var len = buffer.byteLength;
        var uint8buf = new Uint8Array(buffer);
         for (var i = 0; i < len; i++) {
             res += uint8buf[i].toString(16).slice(-2) + ' ';
         }
        return res;
    };

    function testmfl(){
        if (mfl) {
            mfl.push(1);
            console.log("mfl defined, length:"+mfl.length);
            if (mfl.indexOf(1) != -1) {
                console.log("mfl includes 1, length:"+mfl.length);
            } else{
                console.log("mfl don't includes 1, length:"+mfl.length);
            }
        };
    };

	function hookaddr(libname,funcname, addr,n) {
      	 Interceptor.attach (Module.findBaseAddress(libname).add(addr), {
	        onEnter: function(args) {
	            console.warn(" ***" + funcname + " entered open, n="+n);
		        var i = 0;
		        for (i = 0; i < n; i++) {
			        try {
	                    console.log("arg " +i+ ":"+args[i]);
			            if (args[i] > 0x10000000) {
	                        var arg = Memory.readCString(ptr(args[i]));
	                        console.log("arg " +i+ ":"+arg);
			            }
			        } catch(ex) {
                        console.log(ex);
			        };
		        }

                console.log("Backtrace:" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join(""));
            },
	        onLeave: function (retval) {
	            console.log("retval: " + retval);
	        }
	    });
	};
	function hookfunc(libname,funcname,n) {
        Interceptor.attach (Module.findExportByName ( libname, funcname), {
            onEnter: function(args) {
                console.warn(" ***" + funcname + " entered open, n="+n);
		        var i = 0;
		        for (i = 0; i < n; i++) {
			        try {
	                    console.log("arg " +i+ ":"+args[i]);
			            if (args[i] > 0x10000000) {
	                        var arg = Memory.readCString(ptr(args[i]));
	                        console.log("arg " +i+ ":"+arg);
                            var mem = Memory.readByteArray(args[i], 4);
                            console.log("Read bytes: " + mem.byteLength.toString());
                            var buf;
                            if (mem[0] == 0x0A) {
                                console.log("found model file! print 100 byte:");
                                buf = Memory.readByteArray(args[i], 100);
                                bufferToHex(buf); 
                            } else {
	                            console.log("arg " +i+ "in hex(10 bytes):");
                                buf = Memory.readByteArray(args[i], 10);
                                console.log('buf defined:' + bufferToHex(buf));
                            }
			             }
			        } catch(ex) {
                        console.log(ex);
			        }
		        }

                console.log("Backtrace:" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join(""));
            },
	        onLeave: function (retval) {
                console.log("retval: " + retval);
                if (retval > 0x10000000) {
	                var arg = Memory.readCString(ptr(retval));
	                console.log("ret: "+arg);
                }
	        }
	    });
	};
    function hookmmap(){
        Interceptor.attach(Module.getExportByName('libc.so', 'mmap'), {
            onEnter: function (args) {
                this.fd = args[4].toInt32();
                try {
                    if (mfl.indexOf(this.fd) != -1){
	                    console.log("mmap fd : " + this.fd);
                        this.buf = args[0];
                        this.count = args[1].toInt32();
                        this.offset= args[5].toInt32();

                        if (this.count == 699048) {
                            console.log("find CNN_....end!");
                         }

                        console.log("buf:"+this.buf + " this.count:" + this.count + " offset:"+this.offset);
                    };
                } catch(ex) {
                    console.log(ex);
                }
            },
            onLeave: function (result) {
                var bf = result; 
                if (bf != null && bf[0] == 0x84 && bf[1] == 0xAA) {
                    console.log("find CNN_....end!");
                    console.log(hexdump(bf, { length: 64, ansi: true }));
                };
                if (mfl.indexOf(this.fd) != -1){
                    if (bf != null) {
                        if (bf[0] == 0x84 && bf[1] == 0xAA) {
                            console.log(hexdump(bf, { length: 64, ansi: true }));
                        };
                    }
                    console.log('mmap Result   : ' + bf);
                }
            }
        });
    };
    function hookopen(){
        Interceptor.attach(Module.getExportByName('libc.so', 'open'), {
              onEnter: function (args) {
                    this.filefn = args[0].readUtf8String();
                    //if (this.filefn.includes("model") && this.filefn.endsWith(".enc")){
                    if (this.filefn.includes("model")){
                      console.log("open:"+this.filefn);
                    }
              },
              onLeave: function (retval) {
                    //if (this.filefn.includes("model") && this.filefn.endsWith(".enc")){
                    if (this.filefn.includes("model")){
                        if (retval.toInt32() > 0) {
                            /* do something with this.fileDescriptor */
                            console.log("fd:" + retval);
                            console.log("mfl.length:" + mfl.length);
                            console.log("mfl:" + mfl.toString());

                            if ( mfl.indexOf(retval.toInt32()) == -1) {
                                mfl.push(retval.toInt32());
                                console.log("mfl:" + mfl.toString());
                            }
                        }
                    }
              },
        });
    };
    function hooknative(libname, funclist){
        for (var i = 0; i < funclist.length; i++) {
             hookfunc('lib'+libname+'.so', funclist[i], 4);
        }
    };
});
