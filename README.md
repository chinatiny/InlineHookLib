# Inlinehook库的介绍
1. 支持用户和内核两种模式
2. 内核在hook时候挂起了其他cpu，降低挂钩高频函数蓝屏问题
3. 提供函数hook和寄存器hook两种方式


# 函数hook使用范例以hook NtOpenThread为例子：

``` stata
//第一步定义NtOpenThread函数指针类型
typedef NTSTATUS (*fpTypeNtOpenThread)(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL
	);
  
//第二步定义一个inlinehook结构体
InlineHookFunctionSt g_inlineNtOpenThread = { 0 };

//第三步定义一个山寨函数
NTSTATUS FakeNtOpenThread(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId)
{
  //直接调用旧的函数，在这里你可以进行过滤
	fpTypeNtOpenThread pOldFunc = (fpTypeNtOpenThread)g_inlineNtOpenThread.pNewHookAddr;
  return pOldFunc(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
}

 
//第四步开始执行hook
PVOID pfnNtOpenThread = GetSSDTFuncAddrByName("NtOpenThread");
InitInlineHookFunction(&g_inlineNtOpenThread, pfnNtOpenThread, FakeNtOpenThread);
bInstallRet = InstallInlineHookFunction(&g_inlineNtOpenThread);
KdPrint(("NtOpenThread 安装结果:%d\n", bInstallRet));

//第五步当驱动退出的时候，卸载hook
UninstallInlineHookFunction(&g_inlineNtOpenThread);
```

# 寄存器过滤使用范例，以hook NtOpenThread为例子：

``` x86asm
//第一步先用ida查看NtOpenThread确定好我们要hook的位置，假设我们hook的位置是：0065FDA2，相对于函数开始地址偏移为:0x1B
PAGE:0065FD87 ; Exported entry 1113. NtOpenThread
PAGE:0065FD87
PAGE:0065FD87
PAGE:0065FD87 ; Attributes: bp-based frame
PAGE:0065FD87
PAGE:0065FD87 ; __stdcall NtOpenThread(x, x, x, x)
PAGE:0065FD87 public _NtOpenThread@16
PAGE:0065FD87 _NtOpenThread@16 proc near
PAGE:0065FD87
PAGE:0065FD87 PreviousMode= byte ptr -4
PAGE:0065FD87 arg_0= dword ptr  8
PAGE:0065FD87 arg_4= dword ptr  0Ch
PAGE:0065FD87 arg_8= dword ptr  10h
PAGE:0065FD87 arg_C= dword ptr  14h
PAGE:0065FD87
PAGE:0065FD87 mov     edi, edi
PAGE:0065FD89 push    ebp
PAGE:0065FD8A mov     ebp, esp
PAGE:0065FD8C push    ecx
PAGE:0065FD8D mov     eax, large fs:124h
PAGE:0065FD93 mov     al, [eax+13Ah]
PAGE:0065FD99 mov     ecx, [ebp+arg_C]
PAGE:0065FD9C mov     edx, [ebp+arg_8]
PAGE:0065FD9F mov     [ebp+PreviousMode], al
PAGE:0065FDA2 push    dword ptr [ebp+PreviousMode] ; PreviousMode
PAGE:0065FDA5 push    dword ptr [ebp+PreviousMode] ; char
PAGE:0065FDA8 push    [ebp+arg_4]     ; int
PAGE:0065FDAB push    [ebp+arg_0]     ; int
PAGE:0065FDAE call    _PsOpenThread@24 ; PsOpenThread(x,x,x,x,x,x)
PAGE:0065FDB3 leave
PAGE:0065FDB4 retn    10h
PAGE:0065FDB4 _NtOpenThread@16 endp
PAGE:0065FDB4

//第二步定义一个寄存器过滤结构体
InlineRegFilterHookSt g_inlineRegfilterSt = {0};
//第三步定义一个寄存器过滤函数
void _stdcall NtOpenThreadRegFilterReg(HookContex* hookContex)
{
    //在这里做下简单的判断
    if(hookContex->uEax == hookContex->uEbx)
    {
        //如果满足条件当程序运行到NtOpenThread+0x1B的地方会修改eax的值为1
        hookContex->uEax=1；
    }
}
//第四步执行过滤hook
PVOID pfnNtOpenThread = GetSSDTFuncAddrByName("NtOpenThread");
InitRegFilterInlineHook(&g_inlineRegfilterSt, (LVOID)((SIZE_T)pfnNtOpenThread+0X1b), NtOpenThreadRegFilterReg);
bInstallRet = InstallRegFilterInlineHook(&g_inlineRegfilterSt);
KdPrint(("NtOpenThread 寄存器过滤安装结果:%d\n", bInstallRet));
//第四步当程序退出时候卸载hook
UninstallRegFilterInlineHook(g_inlineRegfilterSt);
```

