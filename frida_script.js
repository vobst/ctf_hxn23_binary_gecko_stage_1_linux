console.log("Hello world (from frida)");

Interceptor.attach(Module.findExportByName(null, "ptrace"), {
  onLeave(ret) {
    ret.replace(0);
  },
})

Interceptor.attach(Module.findExportByName(null, "write"), {
  onEnter(args) {
    var vars = ptr("0x800004f98");

    for (let i = 0; i < 13; i++, vars = vars.add(8)) {
      console.log(vars)
      let addr = vars.readPointer();
      console.log(`Addr ${i}: ${addr}`);
      if (addr != 0) {
	console.log(DebugSymbol.fromAddress(addr));
      }
    }
  },
});
