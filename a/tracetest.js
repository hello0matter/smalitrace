Java.perform(function() {
    const TargetClass = Java.use("com.mqunar.libtask.NetHttpConductor");

    TargetClass.doingTask.implementation = function() { // doingTask 没有参数
        console.log("[进入] com.mqunar.libtask.NetHttpConductor.doingTask");

        var threadId = Process.getCurrentThreadId();

        try {
            console.log("  开始 Stalk 线程 " + threadId + " (跟踪指令)...");

            Stalker.follow(threadId, {
                events: {
                    call: false,  // 暂时关闭 call 跟踪，减少噪音
                    ret: false,
                    // --- 关键修改：选择一个 ---
                    exec: true,   // 跟踪每一条指令（非常慢，输出量极大）
                    // block: true, // 或者跟踪基本块（稍快，输出量较少）
                    // -----------------------
                    compile: false
                },
                // --- 关键修改：添加事件接收回调 ---
                onReceive: function (events) {
                    // 解析事件缓冲区
                    // Stalker.parse 返回一个数组，每个元素代表一个事件
                    // 对于 exec 事件，通常是 [address, size]，代表在 address 执行了 size 字节的指令
                    // 对于 block 事件，通常是 [address, size]，代表进入了 address 开始的大小为 size 的基本块
                    var parsedEvents = Stalker.parse(events);

                    // 简单打印事件地址（可以根据需要定制输出格式）
                    // 注意：直接打印所有指令地址会产生海量输出！
                    console.log("Stalker Events (Thread " + threadId + "):");
                    parsedEvents.forEach(function(event) {
                        // event[0] 是指令/块的地址 (NativePointer)
                        // event[1] 是指令/块的大小 (number)
                        // 使用 DebugSymbol.fromAddress 可以尝试获取符号名（如果有的话）
                        console.log("  " + DebugSymbol.fromAddress(event[0]) + " (size: " + event[1] + ")");
                    });

                    // 或者使用 Stalker 内建的格式化（更方便，但也可能很长）
                    // console.log(Stalker.parse(events, { annotate: true, stringify: true }));
                }
                // ------------------------------------
            });

        } catch (e) {
            console.error("  启动 Stalker 失败:", e);
        }

        // 调用原始方法
        const result = this.doingTask(); // 调用原始的 doingTask

        try {
            Stalker.unfollow(threadId); // 停止 Stalk
            Stalker.flush(); // 确保所有缓冲的事件都被发送到 onReceive
            console.log("  停止 Stalk 线程 " + threadId);
        } catch (e) {
            console.error("  停止 Stalk 失败:", e);
        }

        return result;
    };
});
