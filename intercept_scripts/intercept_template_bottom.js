    ;
    // var appname = com.xx.yy;
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
                    // hook malloc and free
                    if (flag_malloc_hooked == false) {
                        hookmalloc();
                        hookfree();
                        flag_malloc_hooked = true;
                    };
                    var target = libnamedic[libname]
                    if (target instanceof Array) {
		                console.log("hooking " + libname);
       	        	    hooknative(libname, libnamedic[libname]);
                    } else { // dictionary
                        console.log("It seems this library has dependencies, let's hook them all!"); 
                        for (var l in target) {
		                    console.log("hooking " + l);
       	        	        hooknative(l, target[l]);
                        }
                    };
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

	function hookfunc(libname,funcname, n) {
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
    // instrument free like function
	function hookfreex(libname,funcname) {
        Interceptor.attach (Module.findExportByName ( libname, funcname), {
              onEnter: function (args) {
                    if (args[0] & 0xf == 0) { // only care about large buffer 
                        console.warn(" ***freex*** " + funcname + " entered open");
                        this.freeptr = args[0];
                        console.log("free some buffer , ptr: "+ args[0]);
                        var buf = Memory.readByteArray(args[0], 100);
                        console.log('buf freed:' + bufferToHex(buf));
                        var bfsize = "freex";
                        dumpFreeBuffer(args[0], 10*1024, args[0], bfsize);
                    }
              },
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
    function printbml(bml) {
        if (bml.length > 0) {
           bml.forEach(function(element) {
               console.log("print big buffer:"+ ptr(element));
                 buf = Memory.readByteArray(ptr(element), 100);
                 bufferToHex(buf); 
           });
        }
    };
    function dumpFreeBuffer(bp, size, fn, bfsize) {
        var fname = '/sdcard/mallocbuffer/'+appname+'/' + fn + '_'+bfsize+'_'+count+ '_10KB.pb';
        count += 1;
        console.log("dump freed large buffer! filename: " + fname);
        var newf = new File(fname, 'wb');
        //var fbuf = Memory.readByteArray(args[0], 1024*1024);
        var fbuf = Memory.readByteArray(bp, size);
        newf.write(fbuf);
        newf.flush();
        newf.close();
    };
    function hookencrypt(libname, funcname) {
        Interceptor.attach (Module.findExportByName ( libname, funcname), {
            onEnter: function (args) {
               console.warn(" ***encrypt/decrypt*** " + funcname + " open");

                this.arg0 = args[0];
                this.arg1 = args[1];
		        var i = 0;
                var n = 6
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
            },
	        onLeave: function (retval) {
               //var args = this.dargs;
               console.warn(" ***encrypt/decrypt*** " + funcname + " before leave ");
               console.log("decrypted/encrypted some buffer , ptr: "+ this.arg1);
               var buf1 = Memory.readByteArray(this.arg0, 100);
               console.log('buf in:' + bufferToHex(buf1));
               var buf2 = Memory.readByteArray(this.arg1, 100);
               console.log('buf out:' + bufferToHex(buf2));
               var bfsize1 = "enc_in";
               dumpFreeBuffer(this.arg0, 10*1024, this.arg0, bfsize1);
               var bfsize2 = "enc_out";
               dumpFreeBuffer(this.arg1, 10*1024, this.arg0, bfsize2);
	        }
	    });
	};
    function hookfree(){
        Interceptor.attach(Module.getExportByName('libc.so', 'free'), {
              onEnter: function (args) {
                    this.freeptr = args[0];
                    //if (bml.indexOf(this.freeptr.toInt32()) != -1) {
                    if (this.freeptr.toInt32() in bml) {
                      console.log("free big buffer > 1MB, ptr: "+ args[0]);
                                 //if( fml.indexOf(this.freeptr.toInt32()) == -1) {
                                    var buf = Memory.readByteArray(args[0], 100);
                                    console.log('buf freed:' + bufferToHex(buf));
                                    var bfsize = bml[this.freeptr.toInt32()];
                                    //dumpFreeBuffer(args[0], 10*1024, args[0]);
                                    dumpFreeBuffer(args[0], 10*1024, args[0], bfsize);
                    }
              },
        });
    };
    function hookmalloc(){
        Interceptor.attach(Module.getExportByName('libc.so', 'malloc'), {
              onEnter: function (args) {
                    this.mallocsz = args[0];
                    if (this.mallocsz > 100*1024) {
                      console.log("malloc big buffer > 1MB, size: "+ args[0]);
                      this.flag = 1;
                    } else { this.flag = 0};

              },
              onLeave: function (retval) {
                  if (this.flag == 1) {
                      console.log("malloc big buffer > 1MB, print buffer pointer: " + retval);
                      //bml.push(retval.toInt32());
                      bml[retval.toInt32()] = this.mallocsz.toInt32();
                  }
              },
        });
    };
    function hooknative(libname, funclist){
        for (var i = 0; i < funclist.length; i++) {
             if (funclist[i].includes('free') || funclist[i].includes('Free')) {
                 hookfreex('lib'+libname+'.so', funclist[i]);
             } else if(funclist[i].includes('encrypt') || funclist[i].includes('decrypt')) {
                 hookencrypt('lib'+libname+'.so', funclist[i]);
             } else {
                 hookfunc('lib'+libname+'.so', funclist[i], 1);
             }
        }
    };
});
