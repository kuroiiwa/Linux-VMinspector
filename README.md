# vm\_inspector

## Test Cases (with examples)
1. Allocating heap memory but not using it

From our tests, calling malloc without using the heap memory resulted in only one or two physical
frames being allocated, the rest of the virtual addresses were unmapped.

This result makes sense because physical frames are only allocated as needed.
In other words, even if data exists in the virtual address space, it will not be mapped
to a physical address until absolutely necessary.

```
============================================
TEST #1: MALLOC
============================================
0x55cd7d8dd430 1cede8000 1 1 1 1
0xdead00000000 0x0 0 0 0 0
0xdead00000000 0x0 0 0 0 0
0xdead00000000 0x0 0 0 0 0
0xdead00000000 0x0 0 0 0 0
0xdead00000000 0x0 0 0 0 0
```


2. Write-fault

We triggered a write fault by allocating heap memory (like in Test #1) and then initializing its
data. After initialization, the page table shows up with many more page table entries (with their
young bit, dirty bit, write bit and user bit set).

These bits are set by the CPU because the data was recently accessed and written to.

```
============================================
TEST #2: WRITE FAULT
============================================
Init
0x55cd7d8e7080 7d98f000 1 1 1 1
0xdead00000000 0x0 0 0 0 0
0xdead00000000 0x0 0 0 0 0
0xdead00000000 0x0 0 0 0 0
0xdead00000000 0x0 0 0 0 0
0x55cd7d8f0080 7d98e000 1 1 1 1
After Write Fault
0x55cd7d8e7080 7d98f000 1 1 1 1
0x55cd7d8e8080 7d989000 1 1 1 1
0x55cd7d8e9080 7d991000 1 1 1 1
0x55cd7d8ea080 7d987000 1 1 1 1
0x55cd7d8eb080 7d986000 1 1 1 1
0x55cd7d8ec080 7d988000 1 1 1 1
0x55cd7d8ed080 7d992000 1 1 1 1
0x55cd7d8ee080 7d98a000 1 1 1 1
0x55cd7d8ef080 7d98d000 1 1 1 1
0x55cd7d8f0080 7d98e000 1 1 1 1
```


3. Read-fault followed by a write

We triggered a page fault by allocating heap memory and then accessing its uninitialized data.
The page table gets populated with numerous entries that have different virtual addresses which
all map to the same physical address.
(Note: These addresses have their young bit and user bit set, while their dirty bit and write bit are unset.)

After writing, the same virtual addresses now map to different physical addresses and have their
dirty bit and write bit updated accordingly.


These observations make sense because the read-fault should result in new page table entries
being added to the page table. The virtual addresses all map to one physical address because
our heap memory was uninitialized. Also, since the dirty bit is only set when data has been modified,
and the write bit is set if the page is writable, it makes sense that these bits are unset
after the read fault.
```
============================================
TEST #3: READ FAULT
============================================
Init
0x55cd7d8f0cd0 7d98e000 1 1 1 1
0xdead00000000 0x0 0 0 0 0
0xdead00000000 0x0 0 0 0 0
0xdead00000000 0x0 0 0 0 0
0xdead00000000 0x0 0 0 0 0
0xdead00000000 0x0 0 0 0 0
After Read Fault
0x55cd7d8f0cd0 7d98e000 1 1 1 1
0x55cd7d8f1cd0 1e0c000 1 0 0 1
0x55cd7d8f2cd0 1e0c000 1 0 0 1
0x55cd7d8f3cd0 1e0c000 1 0 0 1
0x55cd7d8f4cd0 1e0c000 1 0 0 1
0x55cd7d8f5cd0 1e0c000 1 0 0 1
0x55cd7d8f6cd0 1e0c000 1 0 0 1
0x55cd7d8f7cd0 1e0c000 1 0 0 1
0x55cd7d8f8cd0 1e0c000 1 0 0 1
0x55cd7d8f9cd0 1e0c000 1 0 0 1
After Write
0x55cd7d8f0cd0 7d98e000 1 1 1 1
0x55cd7d8f1cd0 7de3a000 1 1 1 1
0x55cd7d8f2cd0 7dddb000 1 1 1 1
0x55cd7d8f3cd0 7ddee000 1 1 1 1
0x55cd7d8f4cd0 7de1b000 1 1 1 1
0x55cd7d8f5cd0 7de38000 1 1 1 1
0x55cd7d8f6cd0 7ddd5000 1 1 1 1
0x55cd7d8f7cd0 7ddff000 1 1 1 1
0x55cd7d8f8cd0 7ded7000 1 1 1 1
0x55cd7d8f9cd0 7ddcf000 1 1 1 1
```

4. Write (without fault)

In our test, the page table before non page-faulting writes is identical to the page table
after the writes have occurred.

This makes sense because if a write doesn't trigger a page fault, then that data must
have already existed in a physical address, so the PTEs remain unchanged.
```
============================================
TEST #4: WRITE (NO PAGE FAULT)
============================================
Before Write
0x55cd7d8fa920 7d990000 1 1 1 1
0x55cd7d8fb920 7de1a000 1 1 1 1
0x55cd7d8fc920 7ded9000 1 1 1 1
0x55cd7d8fd920 7debd000 1 1 1 1
0x55cd7d8fe920 7de33000 1 1 1 1
0x55cd7d8ff920 7dfdc000 1 1 1 1
0x55cd7d900920 7dde0000 1 1 1 1
0x55cd7d901920 7ddf6000 1 1 1 1
0x55cd7d902920 7de31000 1 1 1 1
0x55cd7d903920 7de04000 1 1 1 1
After Write
0x55cd7d8fa920 7d990000 1 1 1 1
0x55cd7d8fb920 7de1a000 1 1 1 1
0x55cd7d8fc920 7ded9000 1 1 1 1
0x55cd7d8fd920 7debd000 1 1 1 1
0x55cd7d8fe920 7de33000 1 1 1 1
0x55cd7d8ff920 7dfdc000 1 1 1 1
0x55cd7d900920 7dde0000 1 1 1 1
0x55cd7d901920 7ddf6000 1 1 1 1
0x55cd7d902920 7de31000 1 1 1 1
0x55cd7d903920 7de04000 1 1 1 1
```

5. Copy-on-write

We printed out the page table for a process before forking and then printed out
the page table of the forked child. The two page tables were identical, as expected,
except that the child's page table had the write bit unset.

Having the child's page table entries read-only makes sense because the child should
not be able to overwrite the parent's pages. If the tries to write, the new data
should be allocated to a different physical address, hence copy-on-write.
```
============================================
TEST #5: COPY ON WRITE
============================================
Parent
0x55cd7d904570 7dc7e000 1 1 1 1
0x55cd7d905570 7de10000 1 1 1 1
0x55cd7d906570 7de14000 1 1 1 1
0x55cd7d907570 7ddd1000 1 1 1 1
0x55cd7d908570 7ddeb000 1 1 1 1
0x55cd7d909570 7de5b000 1 1 1 1
0x55cd7d90a570 7dee9000 1 1 1 1
0x55cd7d90b570 7ded8000 1 1 1 1
0x55cd7d90c570 7df8e000 1 1 1 1
0x55cd7d90d570 7deda000 1 1 1 1
Child
0x55cd7d904570 7dc7e000 1 1 0 1
0x55cd7d905570 7de10000 1 1 0 1
0x55cd7d906570 7de14000 1 1 0 1
0x55cd7d907570 7ddd1000 1 1 0 1
0x55cd7d908570 7ddeb000 1 1 0 1
0x55cd7d909570 7de5b000 1 1 0 1
0x55cd7d90a570 7dee9000 1 1 0 1
0x55cd7d90b570 7ded8000 1 1 0 1
0x55cd7d90c570 7df8e000 1 1 0 1
0x55cd7d90d570 7deda000 1 1 0 1
```
