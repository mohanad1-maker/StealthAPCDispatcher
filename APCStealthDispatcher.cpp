//By AlSch092 @ Github - APC Stealth Dispatcher example
#pragma once
#include <Windows.h>
#include <functional>
#include <thread>
#include <iostream>
#include <tuple>

#ifdef _M_X64  //This example features both shellcode execution and ASM stubs as a fallback, these two routines can be found in CallStub.asm

//4C 8B D1 B8 66 01 00 00 CD 2E C3
extern "C" NTSTATUS _MyNtQueueApcThreadEx(HANDLE ThreadHandle, HANDLE ApcContext, PVOID ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3);

//4C 8B D1 B8 67 01 00 00 CD 2E C3
extern "C" NTSTATUS _MyNtQueueApcThreadEx2(HANDLE ThreadHandle, HANDLE ApcContext, ULONG ApcMode, PVOID ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3);

#endif

class ApcExecutor
{
public:
	ApcExecutor()
	{
		_hWorker = CreateThread(nullptr, 0, WorkerRoutine, nullptr, 0, nullptr);

		if (!_hWorker)
			throw std::runtime_error("Failed to create APC worker thread");

		_NtQueueApcThreadEx2 = reinterpret_cast<NtQueueApcThreadEx2_t>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueueApcThreadEx2"));
	}

	~ApcExecutor()
	{
		if (_hWorker)
		{
			TerminateThread(_hWorker, 0); //fast exit, you can add signalled shutdown if you want
			CloseHandle(_hWorker);
		}
	}

	template<typename Func, typename... Args>
	bool Queue(Func&& f, Args&&... args)
	{
		TaskThunk<Func, Args...>* pThunk = new TaskThunk<Func, Args...>(std::forward<Func>(f), std::forward<Args>(args)...);
		return NT_SUCCESS(CallQueueApc((PAPCFUNC)TaskThunk<Func, Args...>::Thunk, (ULONG_PTR)pThunk));
	}

private:
	HANDLE _hWorker = nullptr;

	using NtQueueApcThreadEx2_t = NTSTATUS(NTAPI*)(HANDLE, HANDLE, ULONG, PVOID, PVOID, PVOID, PVOID);

	NtQueueApcThreadEx2_t _NtQueueApcThreadEx2 = nullptr;

	template<typename Func, typename... Args>
	struct TaskThunk
	{
		Func func;
		std::tuple<Args...> args;

		TaskThunk(Func&& f, Args&&... a) : func(std::forward<Func>(f)), args(std::forward<Args>(a)...) {}

		static void CALLBACK Thunk(ULONG_PTR param)
		{
			std::unique_ptr<TaskThunk> self(reinterpret_cast<TaskThunk*>(param));
			CallWithArgs(self->func, self->args, std::index_sequence_for<Args...>{});
			//std::apply(self->func, self->args); //if you're using C++17 or later, you can comment out the above line and uncomment this one
		}

	private:
		template<std::size_t... I>
		static void CallWithArgs(Func& f, const std::tuple<Args...>& args, std::index_sequence<I...>)  //this can be removed if you're using C++17 and use std::apply instead
		{
			f(std::get<I>(args)...);
		}
	};

	static DWORD WINAPI WorkerRoutine(LPVOID)
	{
		while (true)
		{
			SleepEx(INFINITE, TRUE); // alertable wait
		}
	}

	NTSTATUS CallQueueApc(PAPCFUNC fn, ULONG_PTR param)
	{
		if (_NtQueueApcThreadEx2)
		{
#ifdef _M_X64
			const uint8_t xor_key = 0x48;

			uint8_t shellcode_Ex2[] =  //weakly encrypted shellcode, which will be copied to our allocated region and then decrypted & executed
			{
				0x4C ^ xor_key, 0x8B ^ xor_key, 0xD1 ^ xor_key, 0xB8 ^ xor_key, 0x67 ^ xor_key, 0x01 ^ xor_key, 0x00 ^ xor_key, 0x00 ^ xor_key,
				0xCD ^ xor_key, 0x2E ^ xor_key, 0xC3 ^ xor_key
			};

			DWORD dwOldProt = 0;

			LPVOID shellcodeMemory = VirtualAlloc(NULL, sizeof(shellcode_Ex2), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

			if (!shellcodeMemory)
			{
				std::cerr << "VirtualAlloc failed: " << GetLastError() << std::endl;
				return _MyNtQueueApcThreadEx2(_hWorker, NULL, 0, fn, (PVOID)param, NULL, NULL); //fallback to ASM syscall stub if we can't allocate memory
			}

			for (size_t i = 0; i < sizeof(shellcode_Ex2); ++i)
				((uint8_t*)shellcodeMemory)[i] = shellcode_Ex2[i] ^ xor_key; //decrypt shellcode

			typedef NTSTATUS(*MyNtQueueApcThreadEx2_t)(HANDLE, HANDLE, ULONG, PVOID, PVOID, PVOID, PVOID);
			MyNtQueueApcThreadEx2_t _MyNtQueueApcThreadEx2 = (MyNtQueueApcThreadEx2_t)shellcodeMemory;

			return _MyNtQueueApcThreadEx2(_hWorker, NULL, 0, fn, (PVOID)param, NULL, NULL);
#else //x86's shellcode version is a bit more work to add in since it calls some offset in ntdll in edx register, for now fallback to regular call
			return _NtQueueApcThreadEx2(_hWorker, NULL, 0, fn, (PVOID)param, NULL, NULL); //fallback to low-level winapi
#endif
		}
		else
		{
			// fallback to higher-level API, which can be easily blocked by patching over ntdll.Ordinal8
			return QueueUserAPC(fn, _hWorker, param) ? 0 : -1;
		}
	}

	static bool NT_SUCCESS(NTSTATUS status)
	{
		return status >= 0;
	}
};

int main(void)
{
	ApcExecutor dispatcher;

	for (int i = 0; i < 100; i++) //example of scheduling routines to run in our APC thread, which sleeps forever when nothing is scheduled
	{
		dispatcher.Queue([]
			{
				std::cout << "APC-scheduled routine" << std::endl;
			});

		dispatcher.Queue([](int a = rand(), int b = rand(), int c = rand(), int d = rand())
			{
				std::cout << "Arguments: " << a << ", " << b << ", " << c << ", " << d << std::endl;
			});

		Sleep(1000);
	}

	return 0;
}
