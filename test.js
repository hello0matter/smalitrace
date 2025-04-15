var isSwitchMode = false; // 用于标记是否检测到 Switch 模式

function hookSwitchEntryPoints(libart) {
    libart.enumerateSymbols().forEach(function(symbol) {
        if (symbol.name.includes("ExecuteSwitchImplCpp")) {
            console.log("[+] Hooking Switch entry point:", symbol.name, "@", symbol.address);
            Interceptor.attach(symbol.address, {
                onEnter: function(args) {
                    // 当这个 Hook 被触发时，我们知道进入了 Switch 解释器
                    console.log("[*] Entered Switch Mode via:", symbol.name);
                    isSwitchMode = true; // 可以设置一个标记

                    // 你可以在这里获取 ShadowFrame 等信息进行进一步分析
                    // let ctx = new SwitchImplContext(args[0]); // 根据文章的结构
                    // let shadow_frame = ctx.shadow_frame;
                    // let method_name = shadow_frame.method.PrettyMethod();
                    // console.log("    Method:", method_name);
                },
                onLeave: function(retval) {
                    // 可选：离开时可以重置标记或记录
                    // isSwitchMode = false;
                }
            });
        }
    });
}

Java.perform(function() {
    let libart = Process.findModuleByName("libart.so");
    if (libart) {
        hookSwitchEntryPoints(libart);
    } else {
        console.error("libart.so not found!");
    }

    // 示例：Hook 一个目标方法，看看执行时 isSwitchMode 是否为 true
    /*
    const MyClass = Java.use("com.example.myapp.MyClass");
    MyClass.targetMethod.implementation = function(...args) {
        console.log("Entering targetMethod...");
        isSwitchMode = false; // 重置标记
        let result = this.targetMethod(...args); // 执行原始方法
        console.log("Exiting targetMethod. Was Switch Mode detected during execution?", isSwitchMode);
        return result;
    }
    */
});
