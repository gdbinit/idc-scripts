/*
 * create_and_label_sysent_entries.idc
 * v0.2
 *
 * Quick script to create sysent table structure, apply to struct to table
 * and comment with each syscall name.
 * It will try to find out sysent location and size automatically.
 * If it fails then you have to point to the start and end of the sysent table.
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

/*
 *  find sysent table location using _unix_syscall()
 *  first we find the __got pointer and then read where sysent is located at.
 *  this is the disassembly of interesting unix_syscall part.
__text:FFFFFF800063AF18 48 03 1D D9 51 1C 00                    add     rbx, cs:off_FFFFFF80008000F8
__text:FFFFFF800063AF1F 49 8D 7C 24 04                          lea     rdi, [r12+4]
__text:FFFFFF800063AF24 48 3B 1D CD 51 1C 00                    cmp     rbx, cs:off_FFFFFF80008000F8 <- __got ptr to sysent table
__text:FFFFFF800063AF2B 75 1C                                   jnz     short loc_FFFFFF800063AF49
__text:FFFFFF800063AF2D E8 DE A9 FF FF                          call    _fuword
 */
static find_sysent()
{
    auto location, addr, xref, source, i, cmp_addr, got_addr, sysent_addr;
    // find references to fuword function
    location = LocByName("_fuword");
    if (location == BADADDR)
    {
        Message("Could not find fuword() function!\n");
        return 0;
    }
    else
    {
        for (addr = RfirstB(location); addr != BADADDR; addr = RnextB(location, addr))
        {
            xref = XrefType();
            if (xref == fl_CN || xref == fl_CF)
            {
                source = GetFunctionName(addr);
#ifdef DEBUG
                Message("fuword is called from 0x%lx in %s\n", addr, source);
#endif                
                if (source == "_unix_syscall")
                {
                    cmp_addr = addr;
                    i = 5; // number of instructions to search for
                    while (i > 0)
                    {
                        cmp_addr = FindCode(cmp_addr, SEARCH_UP | SEARCH_NEXT);
                        if (GetMnem(cmp_addr) == "cmp")
                        {
#ifdef DEBUG
                            Message("Found cmp at %lx\n", cmp_addr);
#endif
                            got_addr = GetOperandValue(cmp_addr, 1);
                            if (got_addr != -1)
                            {
                                sysent_addr = Qword(got_addr);
#ifdef DEBUG
                                Message("Got address %lx\n", got_addr);
                                Message("Sysent table starts at %lx\n", sysent_addr);
#endif
                                return sysent_addr;
                            }
                        }
                        i--;
                    }
                }
            }
        }
    }
    return -1;
}

/*
 * the strategy to find end of sysent is to find the first address with a data reference
 * starting at the sysent table start address.
 */
static find_sysent_end(start)
{
    auto addr;
    for (addr = start+1; addr != BADADDR; addr++)
    {
        if (DfirstB(addr) != -1)
        {
#ifdef DEBUG        
            Message("Found valid reference at %lx\n", addr);
#endif
            return addr;
        }
    } 
    return -1;
}

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
    
    /* try to find sysent location and size, else ask the user */
    start = find_sysent();
    if (start != -1)
    {
        end = find_sysent_end(start);
    }
    if (start == -1 || end == -1 )
    {
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
    }

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
    Message("All done, hopefully you have sysent table commented with function names and structure defs applied!\n");
}
