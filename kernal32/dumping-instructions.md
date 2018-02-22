This version if kernal32 is working slightly different (compared to the one
for sirius). The htpac seems to be compiled with a different packing mode which
required some more tweaks.

The packed executable is loaded into a new process and the first stage of the
unpacker runs. It uses your typical GetProcAddress, LoadLibraryA and
GetModuleHandleA holes to build it's own IAT importing all the functions it
needs for it's own job, first. Various anti-debugger checks are also in place
(e.g. IsDebuggerPresent, SetUnhandledExceptionFilter swtiching, 
CheckRemoteDebuggerPresent etc.).

It calls the kernel module (HtsysmNT.sys) which must be loaded. That module
is used as a decryption server. It seems to send some initial data to the server
which generates the decryption key (only a few bytes are exchanged). The
client unpacker (the unpacker code in your packed executable) executes the
actual unpacking of the code + data sections. Once that's finished, the packer
prepares for stage two.

Preparation for stage two involes spawning a child process (CreateRemoteProcess)
and writing to the child's virtual memory. All unpacked segments of the
application are written to the child process. Then, the first stage is complete.
The current process resumes the child process and terminates itself.

The second stage is running in the child process. First, the packer creates
his own IAT for his tasks again. The imports quite similar because it executes
the anti-debugger checks again. After that, it starts reconstructing the IAT
for the target application. Once that's finished, the fourth call to
SetLastError seems to be a good point when the packer has finished all his stuff
and no application code has executed, yet.

We guard all the pages of the sections that contain application code and
install an exception handler to trap the first access to one of the sections.
This worked fine on Sirius and gave us the OEP once the packer made the final
jump to that. However, for some reason this doesn't work on Empress but that's
not a major issue.

Once the exception handler is triggered, the application is still in the right
state for dumping. We do some fix ups which involve stripping a huge chunk
of zeros and dump the remaining data of the sections to an executable. The
OEP yielded is not right but can be easily corrected. Just load up the dumped
executable in IDA and search for something like GetCommandLineA which is
called in the start function when setting up the C runtime. GetVersionExA
should preceed GetCommandLineA and your should be able to spot the start of
the function easily.

Note the address and edit the OEP using something like CFF explorer. Note:
Don't forget to subtract the base of 0x400000 from that value.

Here are the OEPs for the Empress revisions:
2008111900: 0xFAA2B
2008112600: 0xFAF4B
2008120800: 0xFA6EB
2009010600: 0xFA70B
2009072200: 0xFA70B