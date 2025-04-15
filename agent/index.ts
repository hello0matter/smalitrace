import { PrettyInstruction } from "./helper";
import { ShadowFrame, SwitchImplContext } from "./util";

import { log } from "./logger";

function enable_rpc_mode(flag: Boolean){
    rpc_mode = flag;
}

function get_method_name(shadow_frame: ShadowFrame){
    let method_key = shadow_frame.method.toString();
    let method_name: any = method_name_cache[method_key];
    if (!method_name){
        method_name = shadow_frame.method.PrettyMethod();
        if (method_name){
            method_name_cache[method_key] = method_name;
        }
    }
    return method_name;
}

function trace_interpreter_enrty(libart: Module, hook_switch: boolean, hook_mterp: boolean){
    libart.enumerateSymbols().forEach(function(symbol: ModuleSymbolDetails){
        let name = symbol.name;
        let address = symbol.address;

        // Hook ExecuteSwitchImplCpp 入口 (如果 hook_switch 为 true)
        if(name.includes("ExecuteSwitchImplCpp") && hook_switch){
            log(`start hook entry: ${name} at ${address}`);
            Interceptor.attach(address, {
                onEnter(args) {
                    try {
                        let ctx = new SwitchImplContext(args[0]);
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
                        let inst_ptr: NativePointer | null = null;
                        if (ctx.accessor.insns && !ctx.accessor.insns.isNull()) {
                             inst_ptr = ctx.accessor.insns.add(dex_pc);
                        }
                
                        if (inst_ptr && !inst_ptr.isNull() && dexfile_ptr && !dexfile_ptr.isNull()) {
                            inst_str = PrettyInstruction(inst_ptr, dexfile_ptr); // PrettyInstruction 内部返回 string
                            // 可选：进一步处理错误字符串
                            if (inst_str.startsWith("[")) {
                                 inst_str = `指令解析失败(inst=${inst_ptr}, dex=${dexfile_ptr})`;
                            }
                        } else {
                            inst_str = `[指令输入无效(inst=${inst_ptr}, dex=${dexfile_ptr})]`;
                        }
                
                        // 组合更清晰的日志
                        // 格式：[Trace 类型] 线程ID | ShadowFrame地址 | 方法名/错误信息 | 指令/错误信息
                        log(`[SwitchEntry] tid:${Process.getCurrentThreadId()} | SF:${shadow_frame.pointer} | M:${method_display_name} | I:${inst_str}`);
                
                    } catch(e: any) {
                         log(`[SwitchEntry hook error] ${e.message}\n${e.stack}`); // 添加堆栈信息
                    }
                }
            });
        }

        // Hook ExecuteMterpImpl 入口 (如果 hook_mterp 为 true)
        if(name.includes("ExecuteMterpImpl") && hook_mterp){
            log(`start hook entry: ${name} at ${address}`);
            Interceptor.attach(address, {
                onEnter(args) {
                    try { // 添加 try...catch
                        // 注意：这里的参数索引可能需要根据实际 ExecuteMterpImpl 签名调整
                        let inst_ptr = args[1]; // 假设 inst_ptr 是第二个参数
                        let shadow_frame = new ShadowFrame(args[2]); // 假设 shadow_frame 是第三个参数
                        // 直接在入口处获取方法名
                        let method_name = get_method_name(shadow_frame);
                        // 直接在入口处获取指令字符串
                        let dexfile_ptr = shadow_frame.method.GetDexFile();
                        let inst_str = "[指令在入口处未解析]";
                         if (inst_ptr && !inst_ptr.isNull() && dexfile_ptr && !dexfile_ptr.isNull()) {
                            inst_str = PrettyInstruction(inst_ptr, dexfile_ptr);
                        }
                        log(`[entry mterp] tid:${Process.getCurrentThreadId()} ${method_name} ${inst_str}`);
                    } catch(e: any) {
                         log(`[entry mterp hook error] ${e.message}`);
                    }
                }
            });
        }
    })
}

function trace_interpreter_switch(libart: Module, offset: number, frame_reg: string, inst_reg: string) {
    Interceptor.attach(libart.base.add(offset), {
        onEnter(args) {
            let id = switch_count;
            switch_count += 1;
            let ctx = this.context as Arm64CpuContext;
            let shadow_frame = new ShadowFrame(ctx[frame_reg as keyof typeof ctx]);
            // 通过 thread 获取到当前的 shadow_frame
            // let thread_ptr = ctx.sp.add(0x210).sub(0x168).readPointer();
            // let shadow_frame = get_shadow_frame_ptr_by_thread_ptr(thread_ptr);
            let method_name = get_method_name(shadow_frame);
            let dexfile_ptr = shadow_frame.method.GetDexFile();
            let inst_ptr = ctx[inst_reg as keyof typeof ctx];

             // ---> 添加检查 <---
    if (inst_ptr.isNull() || dexfile_ptr.isNull()) {
        log(`[${id}] [switch] Skipping PrettyInstruction: inst_ptr=${inst_ptr}, dexfile_ptr=${dexfile_ptr}`);
        // 可以选择在这里直接 return 或者让 PrettyInstruction 内部处理
    }
    // ---> 结束检查 <---

            let inst_str = PrettyInstruction(inst_ptr, dexfile_ptr);
            log(`[${id}] [switch] ${method_name} `);
        }
    });
}

function hook_mterp_op(address: NativePointer, offset: NativePointer, thread_reg: string, inst_reg: string) {
    Interceptor.attach(address, {
        onEnter(args) {
            let id = mterp_count;
            mterp_count += 1;
            let ctx = this.context as Arm64CpuContext;
            let thread_ptr = ctx[thread_reg as keyof typeof ctx];
            let shadow_frame = get_shadow_frame_ptr_by_thread_ptr(thread_ptr);
            let method_name = get_method_name(shadow_frame);
            let dexfile_ptr = shadow_frame.method.GetDexFile();
            let inst_ptr = ctx[inst_reg as keyof typeof ctx];
            let inst_str = PrettyInstruction(inst_ptr, dexfile_ptr);
            log(`[${id}] [mterp] ${Process.getCurrentThreadId()} ${method_name} ${inst_str}`);
        }
    });
}

function trace_interpreter_mterp_op(libart: Module, thread_reg: string, inst_reg: string) {
    let op_count = 0;
    let symbols = libart.enumerateSymbols();
    for (let index = 0; index < symbols.length; index++) {
        const symbol = symbols[index];
        // 过滤不符合要求的符号
        if (!symbol.name.startsWith("mterp_op_")) continue;
        if (symbol.name.endsWith("_helper")) continue;
        if (symbol.name.endsWith("_quick")) continue;
        if (symbol.name.endsWith("_no_barrier")) continue;
        if (symbol.name.includes("unused")) continue;
        // nop 对应位置的指令太短 hook 会失败 跳过
        if (symbol.name == "mterp_op_nop") continue;
        op_count += 1;
        let hook_addr = symbol.address;
        // return 相关的指令起始就是一个BL frida hook 会失败 需要把hook点向后挪4字节
        if (symbol.name.startsWith("mterp_op_return")) {
            hook_addr = symbol.address.add(0x4);
        }
        let offset = hook_addr.sub(libart.base);
        log(`[mterp_op] ${symbol.name} ${symbol.address} ${hook_addr} ${offset}`);
        // 正式 hook
        hook_mterp_op(hook_addr, offset, thread_reg, inst_reg);
    }
    log(`[mterp_op] op_count ${op_count}`);
}

function find_managed_stack_offset(libart: Module) {
    // 特征
    // 会将某个寄存器偏移一个 pointer 取值到另一个寄存器
    // 被赋值的寄存器会通过 add 指令加上一个偏移得到 managed_stack
    // 这个地方的偏移就是需要的
    let managed_stack_offset: number = -1;
    let thread_reg: any = null;
    let symbols = libart.enumerateSymbols();
    for (let index = 0; index < symbols.length; index++) {
        let symbol = symbols[index];
        // void art::StackVisitor::WalkStack<(art::StackVisitor::CountTransitions)0>(bool)
        if (symbol.name != "_ZN3art12StackVisitor9WalkStackILNS0_16CountTransitionsE0EEEvb") continue;
        let address = symbol.address;
        for (let index = 0; index < 30; index++) {
            if (managed_stack_offset != -1) break;
            let ins = Instruction.parse(address);
            if (ins.mnemonic == "b") break;
            let ins_str = ins.toString();
            // log(`ins_str => ${ins_str}`);
            if (thread_reg == null){
                let thread_reg_re = new RegExp(`ldr (\\w\\d+), \\[\\w\\d+, #${Process.pointerSize}\\]`, "g");;
                // 32 ldr r0, [r4, #4]
                // 64 ldr x8, [x0, #8]
                let results = thread_reg_re.exec(ins_str);
                if (results != null) {
                    thread_reg = results[1];
                    log(`[WalkStack] find thread_reg => ${thread_reg}`);
                }
            } else {
                let managed_stack_offset_re = new RegExp(`add.+?, ${thread_reg}, #(.+)`, "g");
                // 32 add.w sb, r0, #0xac
                // 64 add x23, x8, #0xb8
                let results = managed_stack_offset_re.exec(ins_str);
                if (results != null){
                    managed_stack_offset = Number(results[1]);
                    log(`[WalkStack] find managed_stack_offset => ${managed_stack_offset}`);
                }
            }
            address = ins.next;
        }
    }
    return managed_stack_offset;
}

function get_shadow_frame_ptr_by_thread_ptr(thread_ptr: NativePointer) : ShadowFrame {
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
    return new ShadowFrame(cur_frame_ptr);
}

function main(){
    let libart = Process.findModuleByName("libart.so");
    if (libart == null) {
        log(`libart is null`);
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

export let rpc_mode: Boolean = false;

let method_name_cache: {[key: string]: string} = {};
let switch_count = 0;
let mterp_count = 0;

setImmediate(main);

rpc.exports = {
    go: main,
    enablerpcmode: enable_rpc_mode,
}

// frida -U -n LibChecker -l _agent.js -o trace.log
// frida -U -n com.absinthe.libchecker -l _agent.js -o trace.log
// frida -U -f com.absinthe.libchecker -l _agent.js -o trace.log --no-pause