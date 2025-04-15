import { GetObsoleteDexCache_func, PrettyMethod } from "./helper"; // 确认路径正确
import { log } from "./logger";

export class SwitchImplContext {

    pointer: NativePointer;
    thread_ptr: NativePointer;
    accessor: CodeItemDataAccessor;
    shadow_frame: ShadowFrame;

    constructor (pointer: NativePointer){
        this.pointer = pointer;
        this.thread_ptr = this.pointer.readPointer();
        this.accessor = new CodeItemDataAccessor(this.pointer.add(Process.pointerSize).readPointer());
        this.shadow_frame = new ShadowFrame(this.pointer.add(Process.pointerSize * 2).readPointer());
    }

}


export class CodeItemDataAccessor {

    pointer: NativePointer;
    insns: NativePointer;

    constructor (pointer: NativePointer){
        this.pointer = pointer;
        this.insns = this.pointer.add(Process.pointerSize).readPointer();
    }

    Insns(): NativePointer {
        return this.insns;
    }

}

export class ShadowFrame {

    pointer: NativePointer;
    method: ArtMethod;

    constructor (pointer: NativePointer){
        this.pointer = pointer;
        this.method = new ArtMethod(this.pointer.add(Process.pointerSize).readPointer());
    }

    toString(): string{
        return this.pointer.toString();
    }

    GetDexPC(): number {
        let dex_pc_ptr_ = this.pointer.add(Process.pointerSize * 3).readPointer();
        if (!dex_pc_ptr_.equals(ptr(0x0))){
            let dex_instructions_ = this.pointer.add(Process.pointerSize * 4).readPointer();
            return Number(dex_pc_ptr_.sub(dex_instructions_).toString());
        }
        else{
            return this.pointer.add(Process.pointerSize * 6 + 4).readU32();
        }
            
    }

}

export class ArtMethod {

    pointer: NativePointer;

    constructor (pointer: NativePointer){
        this.pointer = pointer;
    }

    toString(): string {
        return this.pointer.toString();
    }

    PrettyMethod(): string { // 返回 string，包含错误信息
        // 调用 helper.ts 中已优化的 PrettyMethod
        return PrettyMethod(this.pointer);
    }

    GetObsoleteDexCache(): NativePointer { // 返回 NativePointer
        const errorPrefix = `[ArtMethod.GetObsoleteDexCache ArtMethod=${this.pointer}]`;
        // 检查 null，处理飘红
        if (!GetObsoleteDexCache_func) {
            console.error(`${errorPrefix} GetObsoleteDexCache_func 未初始化!`);
            return ptr(0);
        }
        try {
            // 使用 ! 断言或让 TS 通过前面的 if 推断
            const result = GetObsoleteDexCache_func!(this.pointer);
            if (result.isNull()){
                 // console.warn(`${errorPrefix} 原生函数返回了 NULL DexCache 指针`);
            }
            return result;
        } catch (e: any) {
            console.error(`${errorPrefix} 调用原生函数时出错: ${e.message}`); // 移除堆栈以简化日志
            return ptr(0);
        }
    }

    GetDexFile(): NativePointer { // 返回 NativePointer
        const errorPrefix = `[ArtMethod.GetDexFile ArtMethod=${this.pointer}]`;
        try {
            // --- 尝试读取，即使偏移可能错误 ---
            let access_flags = this.pointer.add(0x4).readU32();
            if ((access_flags & 0x40000) != 0){ // Obsolete 方法
                // log(`${errorPrefix} flag indicates ObsoleteMethod => ${access_flags.toString(16)}`);
                // 调用 GetObsoleteDexCache (它内部会处理错误并返回 ptr(0) 或有效指针)
                return this.GetObsoleteDexCache();
            }
            else{
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
        } catch (e: any) {
            // --- 最关键的改动：捕获所有异常，返回 ptr(0) ---
            // console.error(`${errorPrefix} 获取 DexFile 时出错: ${e.message}`); // 减少日志噪音
            // 不再让错误冒泡导致崩溃，而是返回 NULL
            return ptr(0);
        }
    }
}