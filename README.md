# Stealth APC Dispatcher - A stealthy alternative to threads for tasking functions (Windows, C++)  

The `ApcExecutor` class schedules functions to be executed via user APC by using direct syscalls within an encrypted shellcode. Perfect for stealth operations in red-teams, anti-cheat, cheats, etc.  

## How it works  
- Our class creates a 'sleeper' thread on the `WorkerRoutine` function which sleeps infinitely, essentially providing a means to queue APC into.   
- The `Queue` routine uses a function template with parameter pack to create the `TaskThunk` class object using perfect forwarding. We then call `CallQueueApc` using the `Thunk` routine and the newly made `TaskThunk` object  
- The `CallQueueApc` routine contains XOR-encrypted shellcode which mimics `NtQueueApcThreadEx2`. We allocate some memory, copy the decrypted shellcode to that memory, and call the `syscall` stub which maps to `NtQueueApcThreadEx2` function, while passing our function template (the actual routine we want to execute code in, similar to a thread start address) and packed parameters as the arguments to the APC API (`PAPCFUNC fn, ULONG_PTR param`)  
- The class `TaskThunk` uses a `std::tuple` and a function pointer in order to pack any number of arguments to be used in our function pointer `f`. These are the arguments which were passed to the APC API in the previous line    
- The `Thunk` routine is executed via APC, which calls `CallWithArgs` with our function, its arguments, and `std::index_sequence_for` to properly unpack the parameters   
- `CallWithArgs` finally calls the function template `f` using parameter pack expansion (the original function we queued for work in the first place, along with its arguments).  

The high-level explanation is that we are using a `TaskThunk` object as the APC parameter, which holds our actual routine & parameters which we originally queued. We pass the `Thunk` function as the APC routine, which then unpacks the arguments in the `args` tuple and executes the `func` member. This is what provides the illusion of allowing us to pass any number of arguments into the APC routine when usually only a maximum of 3 can be passed to it.  

We use one APC sleeper thread which sleeps infinitely until woken up by a scheduled/queued routine, meaning work can be scheduled without any subsequent calls to `CreateThread`, since queued routines are executed in the context of the sleeper thread. Because we are using encrypted shellcode with a direct `syscall`, execution of our queued tasks cannot be tampered with easily at the usermode level (through API hooking or WINAPI patching). The downside is that routines are "queued" sequentially by the OS, and do not run parallel of eachother (which may imply slower execution times when compared to a pure multi-threaded application).  

Multiple fallback methods are present incase we cannot somehow allocate memory for shellcodes: the file `CallStub.asm` contains assembler routines which mimic `NtQueueApcThreadEx` and `NtQueueApcThreadEx2`, and we also have function pointer lookups which will directly call `NtQueueApcThreadEx2` (although this is not resistant to patches over this routine, which is why shellcode exeuction is the best execution method).  

Since different Windows builds might have different syscall dispatch numbers, you'll want to make sure that 0x166 and 0x167 are the correct ones for `NtQueueApcThreadEx` and `NtQueueApcThreadEx2` on your machine. These can be found by viewing these routines in a disassembler and seeing what number it is in the second instruction of the routine, which usually looks like `mov rax,00000166`. In the worst case when the `NtQueueApcThreadEx2` cannot be located dynamically, the `QueueUserAPC` is used as a fallback method. Some of my other projects have already explored that this routine can be easily blocked by patching over `ntdll!Ordinal8` (on x64), so it's not ideal. The lower-level `NtQueueApcThreadEx` routines can also be patched over, which is why we want to ideally execute our own syscall stub (which gets allocated into memory each time a queued routine is called).  

## Example Output:
```
APC-scheduled routine
Arguments: 26500, 6334, 18467, 41
APC-scheduled routine
Arguments: 29358, 11478, 15724, 19169
APC-scheduled routine
Arguments: 28145, 5705, 24464, 26962
APC-scheduled routine
Arguments: 491, 9961, 16827, 23281
```
