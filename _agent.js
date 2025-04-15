(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.GetObsoleteDexCache_func = exports.DumpString_func = exports.PrettyMethod_func = exports.PrettyInstruction = exports.PrettyMethod = exports.readStdStringRevised = exports.get_DumpString = exports.get_GetObsoleteDexCache = exports.get_PrettyMethod = void 0;
const logger_1 = require("./logger");
// --- NativeFunction 获取 (保持不变) ---
function get_PrettyMethod() {
    let PrettyMethod_ptr = Module.findExportByName("libart.so", "_ZN3art9ArtMethod12PrettyMethodEb");
    if (PrettyMethod_ptr == null) {
        logger_1.log(`libart.so PrettyMethod_ptr is null`);
        return null; // 返回 null 表示失败
    }
    logger_1.log(`PrettyMethod_ptr => ${PrettyMethod_ptr}`);
    try {
        // 确保签名正确：输入 ArtMethod*, bool; 输出 std::string (返回指针数组)
        return new NativeFunction(PrettyMethod_ptr, ["pointer", "pointer", "pointer"], ["pointer", "bool"]);
    }
    catch (e) {
        logger_1.log(`Error creating NativeFunction for PrettyMethod: ${e}`);
        return null;
    }
}
exports.get_PrettyMethod = get_PrettyMethod;
function get_GetObsoleteDexCache() {
    let GetObsoleteDexCache_ptr = Module.findExportByName("libart.so", "_ZN3art9ArtMethod19GetObsoleteDexCacheEv");
    if (GetObsoleteDexCache_ptr == null) {
        logger_1.log(`libart.so GetObsoleteDexCache_ptr is null`);
        return null;
    }
    logger_1.log(`GetObsoleteDexCache_ptr => ${GetObsoleteDexCache_ptr}`);
    try {
        // 输入 ArtMethod*; 输出 mirror::DexCache*
        return new NativeFunction(GetObsoleteDexCache_ptr, "pointer", ["pointer"]);
    }
    catch (e) {
        logger_1.log(`Error creating NativeFunction for GetObsoleteDexCache: ${e}`);
        return null;
    }
}
exports.get_GetObsoleteDexCache = get_GetObsoleteDexCache;
function get_DumpString() {
    let DumpString_ptr = Module.findExportByName("libdexfile.so", "_ZNK3art11Instruction10DumpStringEPKNS_7DexFileE");
    if (DumpString_ptr == null) {
        logger_1.log(`libdexfile.so DumpString_ptr is null`); // 注意是 libdexfile.so
        return null;
    }
    logger_1.log(`DumpString_ptr => ${DumpString_ptr}`);
    try {
        // 输入 Instruction*, const DexFile*; 输出 std::string (返回指针数组)
        return new NativeFunction(DumpString_ptr, ["pointer", "pointer", "pointer"], ["pointer", "pointer"]);
    }
    catch (e) {
        logger_1.log(`Error creating NativeFunction for DumpString: ${e}`);
        return null;
    }
}
exports.get_DumpString = get_DumpString;
// --- std::string 读取函数 (保持最新的稳定版本，清理日志) ---
function readStdStringRevised(strPtr) {
    // 返回值统一为 string，包含错误信息
    if (strPtr.isNull()) {
        return "[错误：传入的结构指针为空]";
    }
    try {
        // 不再打印内部调试日志
        // const val0 = strPtr.readPointer();
        // const val1 = strPtr.add(Process.pointerSize).readPointer();
        // const val2 = strPtr.add(Process.pointerSize * 2).readPointer();
        // const flag = strPtr.readU8();
        // console.log(`[String Layout Debug] Ptr: ${strPtr}, Val@0: ${val0}, Val@8: ${val1}, Val@16: ${val2}, flag: 0x${flag.toString(16)}`);
        // 尝试1: 从偏移 1 读取
        try {
            const result1 = strPtr.add(1).readUtf8String();
            if (result1 !== null && result1.length > 0) {
                return result1; // 成功，直接返回
            }
        }
        catch (e1) { /* 忽略错误, 继续尝试 */ }
        // 尝试2: 从偏移 0 读取
        try {
            const result0 = strPtr.readUtf8String();
            if (result0 !== null && result0.length > 0) {
                return result0; // 成功，直接返回
            }
        }
        catch (e0) { /* 忽略错误, 继续尝试 */ }
        // 所有尝试失败
        const flagForError = strPtr.readU8(); // 只在错误时读取 flag
        return `[解析错误 flag=0x${flagForError.toString(16)}]`;
    }
    catch (e) {
        // console.error(`读取位于 ${strPtr} 的 std::string 时出错: ${e.message}\n${e.stack}`);
        return "[读取 std::string 异常]";
    }
}
exports.readStdStringRevised = readStdStringRevised;
// --- PrettyMethod (优化后) ---
function PrettyMethod(art_method_ptr) {
    const errorPrefix = `[PrettyMethod错误 ArtMethod=${art_method_ptr}]`;
    if (art_method_ptr.isNull()) {
        return `${errorPrefix} 输入指针为空`;
    }
    if (!exports.PrettyMethod_func) {
        return `${errorPrefix} NativeFunction未初始化`;
    }
    try {
        // 调用原生函数
        // let results: NativePointer[] = PrettyMethod_func(art_method_ptr, 0); // 0 for false
        // PrettyMethod 中 (截图 1, 行 108 修改后)
        let results = exports.PrettyMethod_func(art_method_ptr, 0); // 添加 !
        // 检查 results 是否有效 (基本检查)
        if (!results || !Array.isArray(results) || results.length < 3) {
            console.error(`${errorPrefix} 原生调用返回无效结果: ${results}`);
            return `${errorPrefix} 原生返回异常`;
        }
        // 分配内存模拟 std::string 结构体
        let strStructPtr = Memory.alloc(Process.pointerSize * 3);
        // 将 results 数组的内容复制到新分配的内存中 (带检查)
        try {
            strStructPtr.writePointer(results[0]);
            strStructPtr.add(Process.pointerSize).writePointer(results[1]);
            strStructPtr.add(Process.pointerSize * 2).writePointer(results[2]);
        }
        catch (copyError) {
            console.error(`${errorPrefix} 复制原生结果时出错: ${copyError.message}`);
            return `${errorPrefix} 复制结果异常`;
        }
        // 调用读取函数 (它会处理解析错误并返回字符串)
        let parsedString = readStdStringRevised(strStructPtr);
        // 对解析结果做最终判断，如果还是错误信息，加上上下文
        if (parsedString.startsWith("[")) { // 假设错误信息都以 [ 开头
            return `${errorPrefix} ${parsedString}`; // 返回带上下文的错误信息
        }
        else {
            return parsedString; // 返回成功解析的字符串
        }
    }
    catch (e) {
        // 捕获调用或处理过程中的异常
        console.error(`${errorPrefix} 捕获到异常: ${e.message}\n${e.stack}`);
        return `${errorPrefix} 捕获到异常`;
    }
}
exports.PrettyMethod = PrettyMethod;
// --- PrettyInstruction (优化后) ---
function PrettyInstruction(inst_ptr, dexfile_ptr) {
    const errorPrefix = `[PrettyInstruction错误 Inst=${inst_ptr} DexFile=${dexfile_ptr}]`;
    // 检查输入指针
    if (inst_ptr.isNull()) {
        return `${errorPrefix} inst_ptr为空`;
    }
    if (dexfile_ptr.isNull()) {
        return `${errorPrefix} dexfile_ptr为空`;
    }
    // 检查 NativeFunction 是否初始化
    if (!exports.DumpString_func) {
        return `${errorPrefix} NativeFunction未初始化`;
    }
    try {
        // 调用原生函数
        let results = exports.DumpString_func(inst_ptr, dexfile_ptr);
        // 检查 results 是否有效 (基本检查)
        if (!results || !Array.isArray(results) || results.length < 3) {
            console.error(`${errorPrefix} 原生调用返回无效结果: ${results}`);
            return `${errorPrefix} 原生返回异常`;
        }
        // 分配内存模拟 std::string 结构体
        let strStructPtr = Memory.alloc(Process.pointerSize * 3);
        // 将 results 数组的内容复制到新分配的内存中 (带检查)
        try {
            strStructPtr.writePointer(results[0]);
            strStructPtr.add(Process.pointerSize).writePointer(results[1]);
            strStructPtr.add(Process.pointerSize * 2).writePointer(results[2]);
        }
        catch (copyError) {
            console.error(`${errorPrefix} 复制原生结果时出错: ${copyError.message}`);
            return `${errorPrefix} 复制结果异常`;
        }
        // 调用读取函数
        let parsedString = readStdStringRevised(strStructPtr);
        // 对解析结果做最终判断
        if (parsedString.startsWith("[")) {
            return `${errorPrefix} ${parsedString}`;
        }
        else {
            return parsedString;
        }
    }
    catch (e) {
        console.error(`${errorPrefix} 捕获到异常: ${e.message}\n${e.stack}`);
        return `${errorPrefix} 捕获到异常`;
    }
}
exports.PrettyInstruction = PrettyInstruction;
// 确保 DumpString_func 在使用前已经被 get_DumpString() 正确初始化
exports.PrettyMethod_func = get_PrettyMethod();
exports.DumpString_func = get_DumpString();
exports.GetObsoleteDexCache_func = get_GetObsoleteDexCache();
},{"./logger":3}],2:[function(require,module,exports){
(function (setImmediate){(function (){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.rpc_mode = void 0;
const helper_1 = require("./helper");
const util_1 = require("./util");
const logger_1 = require("./logger");
function enable_rpc_mode(flag) {
    exports.rpc_mode = flag;
}
function get_method_name(shadow_frame) {
    let method_key = shadow_frame.method.toString();
    let method_name = method_name_cache[method_key];
    if (!method_name) {
        method_name = shadow_frame.method.PrettyMethod();
        if (method_name) {
            method_name_cache[method_key] = method_name;
        }
    }
    return method_name;
}
function trace_interpreter_enrty(libart, hook_switch, hook_mterp) {
    libart.enumerateSymbols().forEach(function (symbol) {
        let name = symbol.name;
        let address = symbol.address;
        // Hook ExecuteSwitchImplCpp 入口 (如果 hook_switch 为 true)
        if (name.includes("ExecuteSwitchImplCpp") && hook_switch) {
            logger_1.log(`start hook entry: ${name} at ${address}`);
            Interceptor.attach(address, {
                onEnter(args) {
                    try {
                        let ctx = new util_1.SwitchImplContext(args[0]);
                        let shadow_frame = ctx.shadow_frame;
                        let method_key = shadow_frame.method.toString(); // 获取 ArtMethod 指针字符串
                        // 获取方法名
                        let method_name = get_method_name(shadow_frame); // get_method_name 内部应该返回 string
                        // 可选：如果 get_method_name 返回特定错误字符串，可以进一步处理
                        let method_display_name = method_name.startsWith("[") ? `方法名解析失败(${method_key})` : method_name;
                        // 获取指令字符串
                        let inst_str = "[指令无法获取]"; // 默认值
                        let dexfile_ptr = shadow_frame.method.GetDexFile();
                        let dex_pc = shadow_frame.GetDexPC();
                        let inst_ptr = null;
                        if (ctx.accessor.insns && !ctx.accessor.insns.isNull()) {
                            inst_ptr = ctx.accessor.insns.add(dex_pc);
                        }
                        if (inst_ptr && !inst_ptr.isNull() && dexfile_ptr && !dexfile_ptr.isNull()) {
                            inst_str = helper_1.PrettyInstruction(inst_ptr, dexfile_ptr); // PrettyInstruction 内部返回 string
                            // 可选：进一步处理错误字符串
                            if (inst_str.startsWith("[")) {
                                inst_str = `指令解析失败(inst=${inst_ptr}, dex=${dexfile_ptr})`;
                            }
                        }
                        else {
                            inst_str = `[指令输入无效(inst=${inst_ptr}, dex=${dexfile_ptr})]`;
                        }
                        // 组合更清晰的日志
                        // 格式：[Trace 类型] 线程ID | ShadowFrame地址 | 方法名/错误信息 | 指令/错误信息
                        logger_1.log(`[SwitchEntry] tid:${Process.getCurrentThreadId()} | SF:${shadow_frame.pointer} | M:${method_display_name} | I:${inst_str}`);
                    }
                    catch (e) {
                        logger_1.log(`[SwitchEntry hook error] ${e.message}\n${e.stack}`); // 添加堆栈信息
                    }
                }
            });
        }
        // Hook ExecuteMterpImpl 入口 (如果 hook_mterp 为 true)
        if (name.includes("ExecuteMterpImpl") && hook_mterp) {
            logger_1.log(`start hook entry: ${name} at ${address}`);
            Interceptor.attach(address, {
                onEnter(args) {
                    try { // 添加 try...catch
                        // 注意：这里的参数索引可能需要根据实际 ExecuteMterpImpl 签名调整
                        let inst_ptr = args[1]; // 假设 inst_ptr 是第二个参数
                        let shadow_frame = new util_1.ShadowFrame(args[2]); // 假设 shadow_frame 是第三个参数
                        // 直接在入口处获取方法名
                        let method_name = get_method_name(shadow_frame);
                        // 直接在入口处获取指令字符串
                        let dexfile_ptr = shadow_frame.method.GetDexFile();
                        let inst_str = "[指令在入口处未解析]";
                        if (inst_ptr && !inst_ptr.isNull() && dexfile_ptr && !dexfile_ptr.isNull()) {
                            inst_str = helper_1.PrettyInstruction(inst_ptr, dexfile_ptr);
                        }
                        logger_1.log(`[entry mterp] tid:${Process.getCurrentThreadId()} ${method_name} ${inst_str}`);
                    }
                    catch (e) {
                        logger_1.log(`[entry mterp hook error] ${e.message}`);
                    }
                }
            });
        }
    });
}
function trace_interpreter_switch(libart, offset, frame_reg, inst_reg) {
    Interceptor.attach(libart.base.add(offset), {
        onEnter(args) {
            let id = switch_count;
            switch_count += 1;
            let ctx = this.context;
            let shadow_frame = new util_1.ShadowFrame(ctx[frame_reg]);
            // 通过 thread 获取到当前的 shadow_frame
            // let thread_ptr = ctx.sp.add(0x210).sub(0x168).readPointer();
            // let shadow_frame = get_shadow_frame_ptr_by_thread_ptr(thread_ptr);
            let method_name = get_method_name(shadow_frame);
            let dexfile_ptr = shadow_frame.method.GetDexFile();
            let inst_ptr = ctx[inst_reg];
            // ---> 添加检查 <---
            if (inst_ptr.isNull() || dexfile_ptr.isNull()) {
                logger_1.log(`[${id}] [switch] Skipping PrettyInstruction: inst_ptr=${inst_ptr}, dexfile_ptr=${dexfile_ptr}`);
                // 可以选择在这里直接 return 或者让 PrettyInstruction 内部处理
            }
            // ---> 结束检查 <---
            let inst_str = helper_1.PrettyInstruction(inst_ptr, dexfile_ptr);
            logger_1.log(`[${id}] [switch] ${method_name} `);
        }
    });
}
function hook_mterp_op(address, offset, thread_reg, inst_reg) {
    Interceptor.attach(address, {
        onEnter(args) {
            let id = mterp_count;
            mterp_count += 1;
            let ctx = this.context;
            let thread_ptr = ctx[thread_reg];
            let shadow_frame = get_shadow_frame_ptr_by_thread_ptr(thread_ptr);
            let method_name = get_method_name(shadow_frame);
            let dexfile_ptr = shadow_frame.method.GetDexFile();
            let inst_ptr = ctx[inst_reg];
            let inst_str = helper_1.PrettyInstruction(inst_ptr, dexfile_ptr);
            logger_1.log(`[${id}] [mterp] ${Process.getCurrentThreadId()} ${method_name} ${inst_str}`);
        }
    });
}
function trace_interpreter_mterp_op(libart, thread_reg, inst_reg) {
    let op_count = 0;
    let symbols = libart.enumerateSymbols();
    for (let index = 0; index < symbols.length; index++) {
        const symbol = symbols[index];
        // 过滤不符合要求的符号
        if (!symbol.name.startsWith("mterp_op_"))
            continue;
        if (symbol.name.endsWith("_helper"))
            continue;
        if (symbol.name.endsWith("_quick"))
            continue;
        if (symbol.name.endsWith("_no_barrier"))
            continue;
        if (symbol.name.includes("unused"))
            continue;
        // nop 对应位置的指令太短 hook 会失败 跳过
        if (symbol.name == "mterp_op_nop")
            continue;
        op_count += 1;
        let hook_addr = symbol.address;
        // return 相关的指令起始就是一个BL frida hook 会失败 需要把hook点向后挪4字节
        if (symbol.name.startsWith("mterp_op_return")) {
            hook_addr = symbol.address.add(0x4);
        }
        let offset = hook_addr.sub(libart.base);
        logger_1.log(`[mterp_op] ${symbol.name} ${symbol.address} ${hook_addr} ${offset}`);
        // 正式 hook
        hook_mterp_op(hook_addr, offset, thread_reg, inst_reg);
    }
    logger_1.log(`[mterp_op] op_count ${op_count}`);
}
function find_managed_stack_offset(libart) {
    // 特征
    // 会将某个寄存器偏移一个 pointer 取值到另一个寄存器
    // 被赋值的寄存器会通过 add 指令加上一个偏移得到 managed_stack
    // 这个地方的偏移就是需要的
    let managed_stack_offset = -1;
    let thread_reg = null;
    let symbols = libart.enumerateSymbols();
    for (let index = 0; index < symbols.length; index++) {
        let symbol = symbols[index];
        // void art::StackVisitor::WalkStack<(art::StackVisitor::CountTransitions)0>(bool)
        if (symbol.name != "_ZN3art12StackVisitor9WalkStackILNS0_16CountTransitionsE0EEEvb")
            continue;
        let address = symbol.address;
        for (let index = 0; index < 30; index++) {
            if (managed_stack_offset != -1)
                break;
            let ins = Instruction.parse(address);
            if (ins.mnemonic == "b")
                break;
            let ins_str = ins.toString();
            // log(`ins_str => ${ins_str}`);
            if (thread_reg == null) {
                let thread_reg_re = new RegExp(`ldr (\\w\\d+), \\[\\w\\d+, #${Process.pointerSize}\\]`, "g");
                ;
                // 32 ldr r0, [r4, #4]
                // 64 ldr x8, [x0, #8]
                let results = thread_reg_re.exec(ins_str);
                if (results != null) {
                    thread_reg = results[1];
                    logger_1.log(`[WalkStack] find thread_reg => ${thread_reg}`);
                }
            }
            else {
                let managed_stack_offset_re = new RegExp(`add.+?, ${thread_reg}, #(.+)`, "g");
                // 32 add.w sb, r0, #0xac
                // 64 add x23, x8, #0xb8
                let results = managed_stack_offset_re.exec(ins_str);
                if (results != null) {
                    managed_stack_offset = Number(results[1]);
                    logger_1.log(`[WalkStack] find managed_stack_offset => ${managed_stack_offset}`);
                }
            }
            address = ins.next;
        }
    }
    return managed_stack_offset;
}
function get_shadow_frame_ptr_by_thread_ptr(thread_ptr) {
    // 0xB8 是 managed_stack 在 Thread 中的偏移 需要结合IDA分析
    // 如何定位这个偏移
    // void art::StackVisitor::WalkStack<(art::StackVisitor::CountTransitions)0>(bool)
    // _ZN3art12StackVisitor9WalkStackILNS0_16CountTransitionsE0EEEvb
    // 找到这个函数 然后反编译 在开头找到一个 与 0xFFFFFFFFFFFFFFFELL 相与的变量
    // 然后回溯 可以发现它时由传入参数通过偏移取指针再偏移 这个就是 managed_stack 的偏移
    // http://aospxref.com/android-11.0.0_r21/xref/art/runtime/stack.cc#835
    // let managed_stack = thread_ptr.readPointer().add(0xB8);
    let managed_stack = thread_ptr.add(0xB8);
    // 0x10 是 top_shadow_frame_ 在 ManagedStack 中的偏移 结合源码或者IDA可以分析出来
    let cur_frame_ptr = managed_stack.add(0x10).readPointer();
    return new util_1.ShadowFrame(cur_frame_ptr);
}
function main() {
    let libart = Process.findModuleByName("libart.so");
    if (libart == null) {
        logger_1.log(`libart is null`);
        return;
    }
    let hook_switch = true;
    let hook_mterp = false;
    // 仅对 ExecuteSwitchImplCpp 和 ExecuteMterpImpl 调用时 hook 可以得到一些基本调用轨迹 且对APP运行影响很小
    trace_interpreter_enrty(libart, hook_switch, hook_mterp);
    // 对 ExecuteSwitchImplCpp 实际进行 opcode 判断跳转的位置进行 hook 这样可以得到一个函数内具体执行了什么
    // 通过静态分析可以知道
    // - x19 是 shadow_frame
    // - x26 是 inst
    // 调用了 trace_interpreter_switch 记得将 hook_switch 设为 false 避免重复
    // trace_interpreter_switch(libart, 0x2115C8, 'x19', 'x23');
    // trace_interpreter_switch(libart, 0x2115E4, 'x19', 'x23');
    // 进入 ExecuteMterpImpl 后的逻辑就是
    // - 计算opcode 跳转实际处理位置 执行处理
    // - 再立刻计算下一个opcode 马上跳转实际处理位置
    // - 直到执行结束
    // 对每个 opcode 实际处理的位置进行 hook
    // 通过静态分析和实际测试可以知道
    // - x22 是 self 也就是 thread
    // - x20 是 inst
    // trace_interpreter_mterp_op(libart, "x22", "x20");
}
exports.rpc_mode = false;
let method_name_cache = {};
let switch_count = 0;
let mterp_count = 0;
setImmediate(main);
rpc.exports = {
    go: main,
    enablerpcmode: enable_rpc_mode,
};
// frida -U -n LibChecker -l _agent.js -o trace.log
// frida -U -n com.absinthe.libchecker -l _agent.js -o trace.log
// frida -U -f com.absinthe.libchecker -l _agent.js -o trace.log --no-pause
}).call(this)}).call(this,require("timers").setImmediate)

},{"./helper":1,"./logger":3,"./util":4,"timers":6}],3:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.log = void 0;
const index_1 = require("./index");
function log(message) {
    if (index_1.rpc_mode) {
        send({ "type": "log", info: message });
    }
    else {
        console.log(message);
    }
}
exports.log = log;
},{"./index":2}],4:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ArtMethod = exports.ShadowFrame = exports.CodeItemDataAccessor = exports.SwitchImplContext = void 0;
const helper_1 = require("./helper"); // 确认路径正确
class SwitchImplContext {
    constructor(pointer) {
        this.pointer = pointer;
        this.thread_ptr = this.pointer.readPointer();
        this.accessor = new CodeItemDataAccessor(this.pointer.add(Process.pointerSize).readPointer());
        this.shadow_frame = new ShadowFrame(this.pointer.add(Process.pointerSize * 2).readPointer());
    }
}
exports.SwitchImplContext = SwitchImplContext;
class CodeItemDataAccessor {
    constructor(pointer) {
        this.pointer = pointer;
        this.insns = this.pointer.add(Process.pointerSize).readPointer();
    }
    Insns() {
        return this.insns;
    }
}
exports.CodeItemDataAccessor = CodeItemDataAccessor;
class ShadowFrame {
    constructor(pointer) {
        this.pointer = pointer;
        this.method = new ArtMethod(this.pointer.add(Process.pointerSize).readPointer());
    }
    toString() {
        return this.pointer.toString();
    }
    GetDexPC() {
        let dex_pc_ptr_ = this.pointer.add(Process.pointerSize * 3).readPointer();
        if (!dex_pc_ptr_.equals(ptr(0x0))) {
            let dex_instructions_ = this.pointer.add(Process.pointerSize * 4).readPointer();
            return Number(dex_pc_ptr_.sub(dex_instructions_).toString());
        }
        else {
            return this.pointer.add(Process.pointerSize * 6 + 4).readU32();
        }
    }
}
exports.ShadowFrame = ShadowFrame;
class ArtMethod {
    constructor(pointer) {
        this.pointer = pointer;
    }
    toString() {
        return this.pointer.toString();
    }
    PrettyMethod() {
        // 调用 helper.ts 中已优化的 PrettyMethod
        return helper_1.PrettyMethod(this.pointer);
    }
    GetObsoleteDexCache() {
        const errorPrefix = `[ArtMethod.GetObsoleteDexCache ArtMethod=${this.pointer}]`;
        // 检查 null，处理飘红
        if (!helper_1.GetObsoleteDexCache_func) {
            console.error(`${errorPrefix} GetObsoleteDexCache_func 未初始化!`);
            return ptr(0);
        }
        try {
            // 使用 ! 断言或让 TS 通过前面的 if 推断
            const result = helper_1.GetObsoleteDexCache_func(this.pointer);
            if (result.isNull()) {
                // console.warn(`${errorPrefix} 原生函数返回了 NULL DexCache 指针`);
            }
            return result;
        }
        catch (e) {
            console.error(`${errorPrefix} 调用原生函数时出错: ${e.message}`); // 移除堆栈以简化日志
            return ptr(0);
        }
    }
    GetDexFile() {
        const errorPrefix = `[ArtMethod.GetDexFile ArtMethod=${this.pointer}]`;
        try {
            // --- 尝试读取，即使偏移可能错误 ---
            let access_flags = this.pointer.add(0x4).readU32();
            if ((access_flags & 0x40000) != 0) { // Obsolete 方法
                // log(`${errorPrefix} flag indicates ObsoleteMethod => ${access_flags.toString(16)}`);
                // 调用 GetObsoleteDexCache (它内部会处理错误并返回 ptr(0) 或有效指针)
                return this.GetObsoleteDexCache();
            }
            else {
                // --- 沿用之前的假设，但加强保护 ---
                // 注意：这些偏移和读取方式仍需通过逆向确认才能保证正确性
                let declaring_class_ptr = this.pointer.readPointer();
                if (declaring_class_ptr.isNull()) {
                    // console.error(`${errorPrefix} declaring_class_ptr is NULL`);
                    return ptr(0); // 获取不到 Class，无法继续
                }
                let dex_cache_ptr = declaring_class_ptr.add(0x10).readPointer();
                if (dex_cache_ptr.isNull()) {
                    // console.error(`${errorPrefix} dex_cache_ptr is NULL`);
                    return ptr(0); // 获取不到 DexCache，无法继续
                }
                let dex_file_ptr = dex_cache_ptr.add(0x10).readPointer();
                if (dex_file_ptr.isNull()) {
                    // console.warn(`${errorPrefix} dex_file_ptr is NULL`); // DexFile 为空本身可能正常
                }
                // 即使 dex_file_ptr 是 null，也返回它
                return dex_file_ptr;
            }
        }
        catch (e) {
            // --- 最关键的改动：捕获所有异常，返回 ptr(0) ---
            // console.error(`${errorPrefix} 获取 DexFile 时出错: ${e.message}`); // 减少日志噪音
            // 不再让错误冒泡导致崩溃，而是返回 NULL
            return ptr(0);
        }
    }
}
exports.ArtMethod = ArtMethod;
},{"./helper":1}],5:[function(require,module,exports){
// shim for using process in browser
var process = module.exports = {};

// cached from whatever global is present so that test runners that stub it
// don't break things.  But we need to wrap it in a try catch in case it is
// wrapped in strict mode code which doesn't define any globals.  It's inside a
// function because try/catches deoptimize in certain engines.

var cachedSetTimeout;
var cachedClearTimeout;

function defaultSetTimout() {
    throw new Error('setTimeout has not been defined');
}
function defaultClearTimeout () {
    throw new Error('clearTimeout has not been defined');
}
(function () {
    try {
        if (typeof setTimeout === 'function') {
            cachedSetTimeout = setTimeout;
        } else {
            cachedSetTimeout = defaultSetTimout;
        }
    } catch (e) {
        cachedSetTimeout = defaultSetTimout;
    }
    try {
        if (typeof clearTimeout === 'function') {
            cachedClearTimeout = clearTimeout;
        } else {
            cachedClearTimeout = defaultClearTimeout;
        }
    } catch (e) {
        cachedClearTimeout = defaultClearTimeout;
    }
} ())
function runTimeout(fun) {
    if (cachedSetTimeout === setTimeout) {
        //normal enviroments in sane situations
        return setTimeout(fun, 0);
    }
    // if setTimeout wasn't available but was latter defined
    if ((cachedSetTimeout === defaultSetTimout || !cachedSetTimeout) && setTimeout) {
        cachedSetTimeout = setTimeout;
        return setTimeout(fun, 0);
    }
    try {
        // when when somebody has screwed with setTimeout but no I.E. maddness
        return cachedSetTimeout(fun, 0);
    } catch(e){
        try {
            // When we are in I.E. but the script has been evaled so I.E. doesn't trust the global object when called normally
            return cachedSetTimeout.call(null, fun, 0);
        } catch(e){
            // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error
            return cachedSetTimeout.call(this, fun, 0);
        }
    }


}
function runClearTimeout(marker) {
    if (cachedClearTimeout === clearTimeout) {
        //normal enviroments in sane situations
        return clearTimeout(marker);
    }
    // if clearTimeout wasn't available but was latter defined
    if ((cachedClearTimeout === defaultClearTimeout || !cachedClearTimeout) && clearTimeout) {
        cachedClearTimeout = clearTimeout;
        return clearTimeout(marker);
    }
    try {
        // when when somebody has screwed with setTimeout but no I.E. maddness
        return cachedClearTimeout(marker);
    } catch (e){
        try {
            // When we are in I.E. but the script has been evaled so I.E. doesn't  trust the global object when called normally
            return cachedClearTimeout.call(null, marker);
        } catch (e){
            // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error.
            // Some versions of I.E. have different rules for clearTimeout vs setTimeout
            return cachedClearTimeout.call(this, marker);
        }
    }



}
var queue = [];
var draining = false;
var currentQueue;
var queueIndex = -1;

function cleanUpNextTick() {
    if (!draining || !currentQueue) {
        return;
    }
    draining = false;
    if (currentQueue.length) {
        queue = currentQueue.concat(queue);
    } else {
        queueIndex = -1;
    }
    if (queue.length) {
        drainQueue();
    }
}

function drainQueue() {
    if (draining) {
        return;
    }
    var timeout = runTimeout(cleanUpNextTick);
    draining = true;

    var len = queue.length;
    while(len) {
        currentQueue = queue;
        queue = [];
        while (++queueIndex < len) {
            if (currentQueue) {
                currentQueue[queueIndex].run();
            }
        }
        queueIndex = -1;
        len = queue.length;
    }
    currentQueue = null;
    draining = false;
    runClearTimeout(timeout);
}

process.nextTick = function (fun) {
    var args = new Array(arguments.length - 1);
    if (arguments.length > 1) {
        for (var i = 1; i < arguments.length; i++) {
            args[i - 1] = arguments[i];
        }
    }
    queue.push(new Item(fun, args));
    if (queue.length === 1 && !draining) {
        runTimeout(drainQueue);
    }
};

// v8 likes predictible objects
function Item(fun, array) {
    this.fun = fun;
    this.array = array;
}
Item.prototype.run = function () {
    this.fun.apply(null, this.array);
};
process.title = 'browser';
process.browser = true;
process.env = {};
process.argv = [];
process.version = ''; // empty string to avoid regexp issues
process.versions = {};

function noop() {}

process.on = noop;
process.addListener = noop;
process.once = noop;
process.off = noop;
process.removeListener = noop;
process.removeAllListeners = noop;
process.emit = noop;
process.prependListener = noop;
process.prependOnceListener = noop;

process.listeners = function (name) { return [] }

process.binding = function (name) {
    throw new Error('process.binding is not supported');
};

process.cwd = function () { return '/' };
process.chdir = function (dir) {
    throw new Error('process.chdir is not supported');
};
process.umask = function() { return 0; };

},{}],6:[function(require,module,exports){
(function (setImmediate,clearImmediate){(function (){
var nextTick = require('process/browser.js').nextTick;
var apply = Function.prototype.apply;
var slice = Array.prototype.slice;
var immediateIds = {};
var nextImmediateId = 0;

// DOM APIs, for completeness

exports.setTimeout = function() {
  return new Timeout(apply.call(setTimeout, window, arguments), clearTimeout);
};
exports.setInterval = function() {
  return new Timeout(apply.call(setInterval, window, arguments), clearInterval);
};
exports.clearTimeout =
exports.clearInterval = function(timeout) { timeout.close(); };

function Timeout(id, clearFn) {
  this._id = id;
  this._clearFn = clearFn;
}
Timeout.prototype.unref = Timeout.prototype.ref = function() {};
Timeout.prototype.close = function() {
  this._clearFn.call(window, this._id);
};

// Does not start the time, just sets up the members needed.
exports.enroll = function(item, msecs) {
  clearTimeout(item._idleTimeoutId);
  item._idleTimeout = msecs;
};

exports.unenroll = function(item) {
  clearTimeout(item._idleTimeoutId);
  item._idleTimeout = -1;
};

exports._unrefActive = exports.active = function(item) {
  clearTimeout(item._idleTimeoutId);

  var msecs = item._idleTimeout;
  if (msecs >= 0) {
    item._idleTimeoutId = setTimeout(function onTimeout() {
      if (item._onTimeout)
        item._onTimeout();
    }, msecs);
  }
};

// That's not how node.js implements it but the exposed api is the same.
exports.setImmediate = typeof setImmediate === "function" ? setImmediate : function(fn) {
  var id = nextImmediateId++;
  var args = arguments.length < 2 ? false : slice.call(arguments, 1);

  immediateIds[id] = true;

  nextTick(function onNextTick() {
    if (immediateIds[id]) {
      // fn.call() is faster so we optimize for the common use-case
      // @see http://jsperf.com/call-apply-segu
      if (args) {
        fn.apply(null, args);
      } else {
        fn.call(null);
      }
      // Prevent ids from leaking
      exports.clearImmediate(id);
    }
  });

  return id;
};

exports.clearImmediate = typeof clearImmediate === "function" ? clearImmediate : function(id) {
  delete immediateIds[id];
};
}).call(this)}).call(this,require("timers").setImmediate,require("timers").clearImmediate)

},{"process/browser.js":5,"timers":6}]},{},[2])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJhZ2VudC9oZWxwZXIudHMiLCJhZ2VudC9pbmRleC50cyIsImFnZW50L2xvZ2dlci50cyIsImFnZW50L3V0aWwudHMiLCJub2RlX21vZHVsZXMvcHJvY2Vzcy9icm93c2VyLmpzIiwibm9kZV9tb2R1bGVzL3RpbWVycy1icm93c2VyaWZ5L21haW4uanMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUE7Ozs7QUNBQSxxQ0FBK0I7QUFFL0IsbUNBQW1DO0FBQ25DLFNBQWdCLGdCQUFnQjtJQUM1QixJQUFJLGdCQUFnQixHQUFJLE1BQU0sQ0FBQyxnQkFBZ0IsQ0FBQyxXQUFXLEVBQUUsbUNBQW1DLENBQUMsQ0FBQztJQUNsRyxJQUFJLGdCQUFnQixJQUFJLElBQUksRUFBQztRQUN6QixZQUFHLENBQUMsb0NBQW9DLENBQUMsQ0FBQztRQUMxQyxPQUFPLElBQUksQ0FBQyxDQUFDLGVBQWU7S0FDL0I7SUFDRCxZQUFHLENBQUMsdUJBQXVCLGdCQUFnQixFQUFFLENBQUMsQ0FBQztJQUMvQyxJQUFJO1FBQ0Esc0RBQXNEO1FBQ3RELE9BQU8sSUFBSSxjQUFjLENBQUMsZ0JBQWdCLEVBQUUsQ0FBQyxTQUFTLEVBQUUsU0FBUyxFQUFFLFNBQVMsQ0FBQyxFQUFFLENBQUMsU0FBUyxFQUFFLE1BQU0sQ0FBQyxDQUFDLENBQUM7S0FDdkc7SUFBQyxPQUFPLENBQUMsRUFBRTtRQUNSLFlBQUcsQ0FBQyxtREFBbUQsQ0FBQyxFQUFFLENBQUMsQ0FBQztRQUM1RCxPQUFPLElBQUksQ0FBQztLQUNmO0FBQ0wsQ0FBQztBQWRELDRDQWNDO0FBRUQsU0FBZ0IsdUJBQXVCO0lBQ25DLElBQUksdUJBQXVCLEdBQUksTUFBTSxDQUFDLGdCQUFnQixDQUFDLFdBQVcsRUFBRSwwQ0FBMEMsQ0FBQyxDQUFDO0lBQ2hILElBQUksdUJBQXVCLElBQUksSUFBSSxFQUFDO1FBQ2hDLFlBQUcsQ0FBQywyQ0FBMkMs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Q0FDSjtBQTFFRCw4QkEwRUM7O0FDMUlEO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7OztBQ3hMQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSIsImZpbGUiOiJnZW5lcmF0ZWQuanMiLCJzb3VyY2VSb290IjoiIn0=
