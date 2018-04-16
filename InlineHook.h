#pragma once
#include "AntiCheatDriver.h"
#define  _KERNEL_HOOK


#ifdef __cplusplus
extern "C" {
#endif

#ifdef _KERNEL_HOOK
#include <minwindef.h>
#else
#include <windows.h>
#endif

    #define  BACKUPCODE_SIZE  0x200


	//////////////////////////////////////////////////////////////////针对函数的HOOK Begin////////////////////////////////////////////////////////////////////////////

	typedef  struct  _InlineHookFunctionSt
	{
		PVOID lpHookAddr;   //原始被hook的地址
		PVOID pNewHookAddr; //被hook后，不能直接使用原始地址，如果需要调用原来的函数需要使用这个地址
		PVOID lpFakeFuncAddr;   //山寨函数地址
		int nOpcodeMove; //从lpHookAddr点开始计算，需要移动多少指令到movedOpCode
		BYTE backupCode[BACKUPCODE_SIZE];  //当hook恢复的时候,用来还原的指令
		BOOL bHookSucc; //执行是否成功
	}InlineHookFunctionSt;


	/*
	    函数说明： 对函数进行过滤hook
	    参数说明：
	        inlineSt： inline hook的结构体,直接传入一个结构体的指针即可，其他初始化函数会帮我们填充
	        lpHookAddr： 被hook函数地址
	        lpFakeFuncAddr： 山寨函数地址
	*/
	BOOL InitInlineHookFunction(OUT InlineHookFunctionSt* inlineSt, IN PVOID lpHookAddr, IN PVOID lpFakeFuncAddr);



	/*
	    函数说明： 安装函数hook
	    参数说明：
	    inlineSt： 直接传入InitInlineHook初始化的inlineSt即可
	*/
	BOOL InstallInlineHookFunction(IN InlineHookFunctionSt* inlineSt);


	/*
	    函数说明：卸载函数过滤hook
	    参数说明：
	    inlineSt： 直接传入InstallInlineHook使用的inlineSt即可
	*/
	VOID UninstallInlineHookFunction(IN InlineHookFunctionSt* inlineSt);
	//////////////////////////////////////////////////////////////////针对函数的HOOK End/////////////////////////////////////////////////////////////////////////////




	//////////////////////////////////////////////////////////////////针对寄存器的HOOK Begin///////////////////////////////////////////////////////////////////////
	/*
	    1. hook函数执行的时候，各个寄存器的环境，可以通过直接修改这些值对寄存器做过滤
	    2. 可以根据esp对参数进行过滤
	*/
	typedef struct _HookContex
	{
		ULONG uEflags;
		ULONG uEdi;
		ULONG uEsi;
		ULONG uEbp;
		ULONG uEsp;
		ULONG uEbx;
		ULONG uEdx;
		ULONG uEcx;
		ULONG uEax;
	}HookContex;

	//hook函数的指定的类型
	typedef void(_stdcall *fpTypeFilterReg)(HookContex* hookContex);
	typedef  struct  _InlineHookRegFilterSt
	{
		PVOID lpHookAddr;   //被hook的地址
		int nOpcodeMove; //从lpHookAddr点开始计算，需要移动多少指令到movedOpCode
		BYTE backupCode[BACKUPCODE_SIZE];  //当hook恢复的时候,用来还原的指令
		//
		BYTE*  hookEntry;   //hook入口
		BYTE* movedOpCode; //移动的opcode的缓冲区
		fpTypeFilterReg lpFilterReg;  //对寄存器进行hook的回调函数
		BOOL bHookSucc; //hook是否成功
	}InlineRegFilterHookSt;


	/*
	函数说明： 对寄存器进行过滤hook
	参数说明：
		inlineSt： inline hook的结构体,直接传入一个结构体的指针即可，其他初始化函数会帮我们填充
		lpHookAddr： 任意汇编地址开始的地方
		lpNewProc： 新的函数地址
	*/
	BOOL InitRegFilterInlineHook(OUT InlineRegFilterHookSt* inlineSt, IN PVOID lpHookAddr, IN fpTypeFilterReg lpNewProc);




	/*
	函数说明： 安装寄存器过滤hook
	参数说明：
		inlineSt： 直接传入InitInlineHook初始化的inlineSt即可
	*/
	BOOL InstallRegFilterInlineHook(IN InlineRegFilterHookSt* inlineSt);


	/*
	函数说明：卸载寄存器过滤hook
	参数说明：
	    inlineSt： 直接传入InstallInlineHook使用的inlineSt即可
	*/
	VOID UninstallRegFilterInlineHook(IN InlineRegFilterHookSt* inlineSt);

	//////////////////////////////////////////////////////////////////针对寄存器的HOOK End/////////////////////////////////////////////////////////////////////



#ifdef __cplusplus
}
#endif





