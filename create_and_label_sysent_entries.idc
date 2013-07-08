/*
 * create_and_label_sysent_entries.idc
 *
 * Quick script to create sysent table structure, apply to struct to table
 * and comment with each syscall name.
 * You have to point to the start and end of the sysent table.
 * The end is easy to find, just scroll down from the start until you find an address
 * with a data reference.
 * 
 * This is for 64 bits kernels only.
 * Tested with Mountain Lion and Mavericks kernels, IDA 6.4.
 *
 * (c) fG!, 2013 - pedro@coseinc.com
 *
 * Do whatever you want with this code :-)
 *
 */

#include <idc.idc>

// comment to remove debug log messages
#define DEBUG

static main()
{
    auto version, sysentsize, str_start, str_end, start, end, size, nrentries;
    auto i, address, function_name;
    auto struct_id, entry_address;
    version = AskYN(1, "Is target version less than 10.9?");
    if (version == -1)
    {
        Message("User aborted!\n");
        return -1;
    }
    if ((str_start = AskStr("", "Sysent table start address:")) == 0)
    {
        Message("Error on address input!\n");
        return -1;
    }
    if ((str_end = AskStr("", "Sysent table end address:")) == 0)
    {
        Message("Error on address input!\n");
        return -1;
    }
    start = xtol(str_start);
    end   = xtol(str_end);
#ifdef DEBUG
    Message("Version is %d %lx %lx\n", version, start, end);
#endif
    // pre mavericks
    if (version == 1)
    {   
        struct_id = AddStrucEx(-1, "sysent", 0);
        if (struct_id == -1)
        {
            Message("Error! Can't create structure!\n");
            return -1;
        }
        // no error checking, no fear!
        AddStrucMember(struct_id, "sy_narg", -1, FF_WORD, -1, 2);
        SetMemberComment(struct_id, 0, "/* number of args */", 0);
        AddStrucMember(struct_id, "sy_resv", -1, FF_BYTE, -1, 1);
        SetMemberComment(struct_id, 2, "/* reserved  */", 0);
        AddStrucMember(struct_id, "sy_flags", -1, FF_BYTE, -1, 1);
        SetMemberComment(struct_id, 3, "/* flags */", 0);
        AddStrucMember(struct_id, "padding1", -1, FF_DWRD, -1, 4);
        AddStrucMember(struct_id, "sy_call", -1, FF_QWRD, -1, 8);
        SetMemberComment(struct_id, 8, "/* implementing function */", 0);
        AddStrucMember(struct_id, "sy_arg_munge32", -1, FF_QWRD, -1, 8);
        SetMemberComment(struct_id, 16, "/* system call arguments munger for 32-bit process */", 0);
        AddStrucMember(struct_id, "sy_arg_munge64", -1, FF_QWRD, -1, 8);
        SetMemberComment(struct_id, 24, "/* system call arguments munger for 64-bit process */", 0);
        AddStrucMember(struct_id, "sy_return_type", -1, FF_DWRD, -1, 4);
        SetMemberComment(struct_id, 32, "/* system call return types */", 0);
        AddStrucMember(struct_id, "sy_arg_bytes", -1, FF_WORD, -1, 2);
        SetMemberComment(struct_id, 36, "/* Total size of arguments in bytes for 32-bit system calls */", 0);
        AddStrucMember(struct_id, "padding2", -1, FF_WORD, -1, 2);

        sysentsize = 40;
        nrentries = (end - start + 1) / sysentsize;
#ifdef DEBUG
        Message("Nr of entries %d\n", nrentries);
#endif
        // apply structure and add comment with syscall name
        for (i = 0; i < nrentries; i++)
        {
            entry_address = start + i * sysentsize;
            address = Qword(entry_address + 8);
            function_name = GetFunctionName(address);
            MakeStructEx(entry_address, -1, "sysent");
            MakeComm(entry_address, function_name);
#ifdef DEBUG
            Message("Function at address %lx is %s\n", address, function_name);
#endif
        }
    }
    // mavericks
    else if (version == 0)
    {
        struct_id = AddStrucEx(-1, "sysent", 0);
        if (struct_id == -1)
        {
            Message("Error! Can't create structure!\n");
            return -1;
        }
        // no error checking, no fear!
        AddStrucMember(struct_id, "sy_call", -1, FF_QWRD, -1, 8);
        SetMemberComment(struct_id, 0, "/* implementing function */", 0);
        AddStrucMember(struct_id, "sy_arg_munge32", -1, FF_QWRD, -1, 8);
        SetMemberComment(struct_id, 8, "/* system call arguments munger for 32-bit process */", 0);
        AddStrucMember(struct_id, "sy_arg_munge64", -1, FF_QWRD, -1, 8);
        SetMemberComment(struct_id, 16, "/* system call arguments munger for 64-bit process */", 0);
        AddStrucMember(struct_id, "sy_return_type", -1, FF_DWRD, -1, 4);
        SetMemberComment(struct_id, 24, "/* system call return types */", 0);
        AddStrucMember(struct_id, "sy_narg", -1, FF_WORD, -1, 2);
        SetMemberComment(struct_id, 28, "/* number of args */", 0);
        AddStrucMember(struct_id, "sy_arg_bytes", -1, FF_WORD, -1, 2);
        SetMemberComment(struct_id, 30, "/* Total size of arguments in bytes for 32-bit system calls */", 0);

        sysentsize = 32;
        nrentries = (end - start + 1) / sysentsize;
#ifdef DEBUG
        Message("Nr of entries %d\n", nrentries);
#endif
        for (i = 0; i < nrentries; i++)
        {
            entry_address = start + i * sysentsize;
            address = Qword(entry_address);
            function_name = GetFunctionName(address);
            MakeStructEx(entry_address, -1, "sysent");
            MakeComm(entry_address, function_name);
#ifdef DEBUG
            Message("Function at address %lx is %s\n", address, function_name);
#endif
        }        
    }
    Message("All done, hopefully you have sysent table commented with function names!\n");
}

/*
AddStrucMember 
AddStrucEx
GetFirstMember 
GetFirstStrucIdx 
GetLastMember 
GetLastStrucIdx 
MakeStructEx
SetMemberName
SetMemberType 
SetStrucComment 
SetStrucName 
FFFFFF8000861690
FFFFFF8000864F70
*/