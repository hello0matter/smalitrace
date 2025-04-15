import { log } from "./logger";

// --- NativeFunction 获取 (保持不变) ---
export function get_PrettyMethod(){
    let PrettyMethod_ptr =  Module.findExportByName("libart.so", "_ZN3art9ArtMethod12PrettyMethodEb");
    if (PrettyMethod_ptr == null){
        log(`libart.so PrettyMethod_ptr is null`);
        return null; // 返回 null 表示失败
    }
    log(`PrettyMethod_ptr => ${PrettyMethod_ptr}`);
    try {
        // 确保签名正确：输入 ArtMethod*, bool; 输出 std::string (返回指针数组)
        return new NativeFunction(PrettyMethod_ptr, ["pointer", "pointer", "pointer"], ["pointer", "bool"]);
    } catch (e) {
        log(`Error creating NativeFunction for PrettyMethod: ${e}`);
        return null;
    }
}

export function get_GetObsoleteDexCache(){
    let GetObsoleteDexCache_ptr =  Module.findExportByName("libart.so", "_ZN3art9ArtMethod19GetObsoleteDexCacheEv");
    if (GetObsoleteDexCache_ptr == null){
        log(`libart.so GetObsoleteDexCache_ptr is null`);
        return null;
    }
    log(`GetObsoleteDexCache_ptr => ${GetObsoleteDexCache_ptr}`);
     try {
        // 输入 ArtMethod*; 输出 mirror::DexCache*
        return new NativeFunction(GetObsoleteDexCache_ptr, "pointer", ["pointer"]);
     } catch (e) {
        log(`Error creating NativeFunction for GetObsoleteDexCache: ${e}`);
        return null;
     }
}


export function get_DumpString(){
    let DumpString_ptr =  Module.findExportByName("libdexfile.so", "_ZNK3art11Instruction10DumpStringEPKNS_7DexFileE");
    if (DumpString_ptr == null){
        log(`libdexfile.so DumpString_ptr is null`); // 注意是 libdexfile.so
        return null;
    }
    log(`DumpString_ptr => ${DumpString_ptr}`);
    try {
         // 输入 Instruction*, const DexFile*; 输出 std::string (返回指针数组)
        return new NativeFunction(DumpString_ptr, ["pointer", "pointer", "pointer"], ["pointer", "pointer"]);
    } catch (e) {
        log(`Error creating NativeFunction for DumpString: ${e}`);
        return null;
    }
}




// --- std::string 读取函数 (保持最新的稳定版本，清理日志) ---
export function readStdStringRevised(strPtr: NativePointer): string {
    // 返回值统一为 string，包含错误信息
    if (strPtr.isNull()) { return "[错误：传入的结构指针为空]"; }

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
        } catch (e1: any) { /* 忽略错误, 继续尝试 */ }

        // 尝试2: 从偏移 0 读取
        try {
            const result0 = strPtr.readUtf8String();
             if (result0 !== null && result0.length > 0) {
                return result0; // 成功，直接返回
             }
        } catch (e0: any) { /* 忽略错误, 继续尝试 */ }

        // 所有尝试失败
        const flagForError = strPtr.readU8(); // 只在错误时读取 flag
        return `[解析错误 flag=0x${flagForError.toString(16)}]`;

    } catch (e: any) {
        // console.error(`读取位于 ${strPtr} 的 std::string 时出错: ${e.message}\n${e.stack}`);
        return "[读取 std::string 异常]";
    }
}

// --- PrettyMethod (优化后) ---
export function PrettyMethod(art_method_ptr: NativePointer): string { // 返回 string，包含错误信息
    const errorPrefix = `[PrettyMethod错误 ArtMethod=${art_method_ptr}]`;

    if (art_method_ptr.isNull()) {
        return `${errorPrefix} 输入指针为空`;
    }
    if (!PrettyMethod_func) {
         return `${errorPrefix} NativeFunction未初始化`;
    }

    try {
        // 调用原生函数
        // let results: NativePointer[] = PrettyMethod_func(art_method_ptr, 0); // 0 for false
// PrettyMethod 中 (截图 1, 行 108 修改后)
        let results: NativePointer[] = PrettyMethod_func!(art_method_ptr, 0); // 添加 !

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
        } catch (copyError: any) {
             console.error(`${errorPrefix} 复制原生结果时出错: ${copyError.message}`);
             return `${errorPrefix} 复制结果异常`;
        }

        // 调用读取函数 (它会处理解析错误并返回字符串)
        let parsedString = readStdStringRevised(strStructPtr);

        // 对解析结果做最终判断，如果还是错误信息，加上上下文
        if (parsedString.startsWith("[")) { // 假设错误信息都以 [ 开头
             return `${errorPrefix} ${parsedString}`; // 返回带上下文的错误信息
        } else {
             return parsedString; // 返回成功解析的字符串
        }

    } catch (e: any) {
        // 捕获调用或处理过程中的异常
        console.error(`${errorPrefix} 捕获到异常: ${e.message}\n${e.stack}`);
        return `${errorPrefix} 捕获到异常`;
    }
}
// --- PrettyInstruction (优化后) ---
export function PrettyInstruction(inst_ptr: NativePointer, dexfile_ptr: NativePointer): string { // 返回 string，包含错误信息
    const errorPrefix = `[PrettyInstruction错误 Inst=${inst_ptr} DexFile=${dexfile_ptr}]`;

    // 检查输入指针
    if (inst_ptr.isNull()) {
         return `${errorPrefix} inst_ptr为空`;
    }
     if (dexfile_ptr.isNull()) {
         return `${errorPrefix} dexfile_ptr为空`;
    }
    // 检查 NativeFunction 是否初始化
    if (!DumpString_func) {
         return `${errorPrefix} NativeFunction未初始化`;
    }

    try {
        // 调用原生函数
        let results: NativePointer[] = DumpString_func(inst_ptr, dexfile_ptr);

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
        } catch (copyError: any) {
            console.error(`${errorPrefix} 复制原生结果时出错: ${copyError.message}`);
            return `${errorPrefix} 复制结果异常`;
        }


        // 调用读取函数
        let parsedString = readStdStringRevised(strStructPtr);

        // 对解析结果做最终判断
        if (parsedString.startsWith("[")) {
             return `${errorPrefix} ${parsedString}`;
        } else {
             return parsedString;
        }

    } catch (e: any) {
        console.error(`${errorPrefix} 捕获到异常: ${e.message}\n${e.stack}`);
        return `${errorPrefix} 捕获到异常`;
    }
}
// 确保 DumpString_func 在使用前已经被 get_DumpString() 正确初始化

export let PrettyMethod_func: NativeFunction<[NativePointer,NativePointer,NativePointer], [NativePointer, number]> | null = get_PrettyMethod();
export let DumpString_func: NativeFunction<[NativePointer,NativePointer,NativePointer], [NativePointer, NativePointer]> | null = get_DumpString();
export let GetObsoleteDexCache_func: NativeFunction<NativePointer, [NativePointer]> | null = get_GetObsoleteDexCache();