# z3ncoder
Alphanumeric shellcode encoder modified from [alpha3](https://github.com/SkyLined/alpha3)

## Requirements

```shell
pip3 install -U z3-solver
pip3 install -U pwn
```

## Examples

```python
encoder = Z3ncoder()

print('i386 examples execve("/bin/sh", NULL, NULL):')
pwn.context.arch = 'i386'
pwn.context.bits = 32
shellcode = pwn.asm(pwn.shellcraft.sh())
for start in ['eax', '[eax]', '[ebp]', '[ebp-0x10]', '[esp]', '[esp+0x4]']:
    alnumsc = encoder.encode(shellcode, start)
    print('%s:\n%s\n' % (start, alnumsc.decode('utf-8')))

print('amd64 examples execve("/bin/sh", NULL, NULL):')
pwn.context.arch = 'amd64'
pwn.context.bits = 64
shellcode = pwn.asm(pwn.shellcraft.sh())
for start in ['rax', '[rax]', '[rbp]', '[rbp-0x10]', '[rsp]', '[rsp+0x8]']:
    alnumsc = encoder.encode(shellcode, start)
    print('%s:\n%s\n' % (start, alnumsc.decode('utf-8')))
```

Results:

```
i386 examples execve("/bin/sh", NULL, NULL):
eax:
PYhffffk4diXFkDqm02Dqn0D1DuEEbObjbGfmaufmbTbnara3gLa8ctdAglaSfOaPaCcpa7asgna8bYaRaudmbpbmaXbXabdGgNcxdqb0dQa9aKbYcjcqaC

[eax]:
1030VYhZZZZk4dwXFkDqq02Dqr0D1HuEEbObjbGfmaufmbTbnara3gLa8ctdAglaSfOaPaCcpa7asgna8bYaRaudmbpbmaXbXabdGgNcxdqb0dQa9aKbYcjcqaC

[ebp]:
UY1131VYhiiiik4dfXFkDqs02Dqt0D1JuEEbObjbGfmaufmbTbnara3gLa8ctdAglaSfOaPaCcpa7asgna8bYaRaudmbpbmaXbXabdGgNcxdqb0dQa9aKbYcjcqaC

[ebp-0x10]:
Uh97c3TY1939Xhlb6619k90XX148348VYhPPPPk4dfXFkDqx02Dqy0D1YuEEbObjbGfmaufmbTbnara3gLa8ctdAglaSfOaPaCcpa7asgna8bYaRaudmbpbmaXbXabdGgNcxdqb0dQa9aKbYcjcqaC

[esp]:
14d34dVYhZZZZk4dwXFkDqs02Dqt0D1JuEEbObjbGfmaufmbTbnara3gLa8ctdAglaSfOaPaCcpa7asgna8bYaRaudmbpbmaXbXabdGgNcxdqb0dQa9aKbYcjcqaC

[esp+0x4]:
ThoO92TY1939Xhi2xm19k9VXX148348VYhDDDDk4dxXFkDqx02Dqy0D1YuEEbObjbGfmaufmbTbnara3gLa8ctdAglaSfOaPaCcpa7asgna8bYaRaudmbpbmaXbXabdGgNcxdqb0dQa9aKbYcjcqaC

amd64 examples execve("/bin/sh", NULL, NULL):
rax:
Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3MbGbjbocJaua0a6bmaUfnajbraPbIeOdEa5bsglaWfOcpanavaCaPaaaSaHdSbybnfmgoaMaSdUbQbDcxdqagema9fkbYaQaTaF

[rax]:
H10H30Vh0666TY1131Xh333311k13XjkV11Hc1ZXYf1TqKHf9kDqY02DqZ0D1Lu3MbGbjbocJaua0a6bmaUfnajbraPbIeOdEa5bsglaWfOcpanavaCaPaaaSaHdSbybnfmgoaMaSdUbQbDcxdqagema9fkbYaQaTaF

[rbp]:
UYH11H31Vh0666TY1131Xh333311k13XjjV11Hc1ZXYf1TqKHf9kDqY02DqZ0D1Mu3MbGbjbocJaua0a6bmaUfnajbraPbIeOdEa5bsglaWfOcpanavaCaPaaaSaHdSbybnfmgoaMaSdUbQbDcxdqagema9fkbYaQaTaF

[rbp-0x10]:
UhYZZrTY1131Xhjiia11k1PXVHc9XXH148H348Vh0666TY1131Xh333311k13XjkV11Hc1ZXYf1TqkHf9kDqy02Dqz0D1lu3MbGbjbocJaua0a6bmaUfnajbraPbIeOdEa5bsglaWfOcpanavaCaPaaaSaHdSbybnfmgoaMaSdUbQbDcxdqagema9fkbYaQaTaF

[rsp]:
H14dH34dVh0666TY1131Xh333311k13XjjV11Hc1ZXYf1TqKHf9kDqY02DqZ0D1Mu3MbGbjbocJaua0a6bmaUfnajbraPbIeOdEa5bsglaWfOcpanavaCaPaaaSaHdSbybnfmgoaMaSdUbQbDcxdqagema9fkbYaQaTaF

[rsp+0x8]:
Th93ZyTY1131XhaPxD11k1CXVHc9XXH148H348Vh0666TY1131Xh333311k13XjkV11Hc1ZXYf1TqkHf9kDqy02Dqz0D1lu3MbGbjbocJaua0a6bmaUfnajbraPbIeOdEa5bsglaWfOcpanavaCaPaaaSaHdSbybnfmgoaMaSdUbQbDcxdqagema9fkbYaQaTaF
```


## References

1. https://github.com/SkyLined/alpha3
2. https://github.com/veritas501/ae64
