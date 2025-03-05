#! /usr/bin/python
# program: forth2s.py
# Compile a .forth file to a .s file.

# License: GPL
# Jose Dinuncio <jdinunci@uc.edu.ve>, 12/2009
import re
#import commands


# Option parser
from optparse import OptionParser
parser = OptionParser()
parser.add_option('-i', dest='finname', default='/dev/stdin',
                  help='Name of the input file')
parser.add_option('-o', dest='foutname', default='/dev/stdout',
                  help='Name of the output file')


# ============================================================================
#   States of the translator
# ============================================================================
def copy_lines(fin, fout):
    '''
    function: copy_lines
      Copy lines from fin to fout.

      If the line starts with ':' then start to translate the lines from forth
      to nasm.

    Params:
        fin - file to read.
        fout - file to write.
    '''
    for line in fin:
        if line.startswith(':'):
            defword = translate_forth_def(line)
            fout.write(defword)
            fout.write('\n')
            translate_lines(fin, fout)
        else:
            fout.write(line)

def translate_lines(fin, fout):
    '''
    function: translate_lines
    Translate lines of forth code to nasm assembler.

    The forth code must end in a line beginning with a semicolon.

    The only comments accepted are line comments. They start with a '#'.

    Params:
        fin - file to read.
        fout - file to write.
    '''
    for line in fin:
        if line.startswith(';'):
            fout.write('        dd exit\n')
            return

        for assembly in translate(line):
            fout.write('        %s\n' % assembly)



# ============================================================================
#   Scanner for the translate_lines state
# ============================================================================
def forth_comment(scanner, token):
    '''
    function: forth_comment
       Translate a forth comment into an assembly comment.

       A forth comment starts with the '(' token  and end with the ')' token.
       It must end in the same line it started.
    '''
    return ['; %s' % token[1:-1]]

def line_comment(scanner, token):
    '''
    function: line_comment
       Translate a forth line comment into an assembly comment.

       In this forth, a line comment starts with ';' and ends with the line.
    '''
    return ['; %s' % token[1:]]

def asm_literal(scanner, token):
    '''
    function: asm_literal
       Insert assembly code in a forth word.

       The assembly code is limited by '{' and '}'. Each line of nasm assembly
       is separated by ';'. The assembly literal must end in the same line.
    '''
    asm = token[1:-1].split(';')
    return asm

def literal(scanner, token):
    '''
    function: literal
       Translate a literal word to assembly.
    '''
    return ['litn %s' % token]

def word_literal(scanner, token):
    '''
    function: word_literal
       Translate a ['] forth expression to assembly.

       In this forth we use [`] instead, for the syntax highlighting.
    '''
    return ['litn %s' % token.split()[1]]

def word(scanner, token):
    '''
    function: word
       Translate a forth word.

       The forth word can be a translate to a literal, a macro or a forth word.
    '''
    if token in MACROS:
        return [token]
    elif token in LITERALS:
        return ['litn %s' % token]
    elif token in SYMBOLS:
        return ['dd %s' % SYMBOLS[token]]
    else:
        return ['dd %s' % token]

scanner = re.Scanner([
    (r'\(\s.*\s\)',             forth_comment),
    (r';.*',                    line_comment),
    (r'\{\s.*\}',               asm_literal),
    (r"'.'",                    literal),
    (r'0[xX][0-9A-Fa-f]+',      literal),
    (r'\d+\s',                  literal),
    (r"\[`\]\s+\S+",            word_literal),
    (r'\S+',                    word),
    (r'\s+',                    None),
])

def translate(line):
    trans, remainder = scanner.scan(line)
    return sum([ts for ts in trans], [])


# ============================================================================
#   Support functions
# ============================================================================
def translate_forth_def(line):
    '''
    function: translate_forth_def
      Translate the definition of a forth word to nasm assembly.

      The forth definition must start at the begining of line, and must have the
      following structure:

          : name, label, flags

    Where:
        name - The name of the forth word, as seen for other forth words.
        label - The name of the forth word, as seen by assembly code.
        flags - Flags of this forth word. See forth_core.s and forth_macros.s
                for more details.

    Params:
        line - The first line of a forth word definition

    Returns:
        string - A line of text with the defword of the forth word being defined.
    '''
    defword = 'defword ' + line[1:-1]
    return defword


def get_symbols():
    '''
    function: get_symbols
      Returns a dict wich associate forth words with its assembly labels. It
      is used to translate forth words with symbols in it.
    '''
    dct = {}
    #lines = commands.getoutput("grep '^def[vcw]' *.s *.fth").splitlines()
    #lines.extend(commands.getoutput("grep '^: ' *.fth").splitlines())
    lines = []
    lines.append("forth_core.s:defvar STATE, STATE, 0, 0")
    lines.append("forth_core.s:defvar HERE, HERE, 0, 0")
    lines.append("forth_core.s:defvar LATEST, LATEST, 0, main ; SySCALL0 must be last in built-in dictionary")
    lines.append("forth_core.s:defvar S0, S0, 0, 0")
    lines.append("forth_core.s:defvar BASE, BASE, 0, 10")
    lines.append("forth_core.s:defconst VERSION, VERSION, 0, 1")
    lines.append("forth_core.s:defconst R0, R0, 0, 2")
    lines.append("forth_core.s:defconst DOCOL, __DOCOL, 0, DOCOL")
    lines.append("forth_core.s:defconst F_IMMED, __F_IMMED, 0, 0x80")
    lines.append("forth_core.s:defconst F_HIDDEN, __F_HIDDEN, 0, 0x20")
    lines.append("forth_core.s:defconst F_LENMASK, __F_LENMASK, 0, 0x1f")
    lines.append("forth_core.s:defcode exit, exit, 0")
    lines.append("forth_words.s:defcode stop, stop, 0")
    lines.append("forth_words.s:defcode lit, lit, 0")
    lines.append("forth_words.s:defcode drop, drop,0")
    lines.append("forth_words.s:defcode swap, swap,0")
    lines.append("forth_words.s:defcode dup, dup, 0")
    lines.append("forth_words.s:defcode over, over, 0")
    lines.append("forth_words.s:defcode rot, rot, 0")
    lines.append("forth_words.s:defcode -rot, nrot, 0")
    lines.append("forth_words.s:defcode 2drop, twodrop, 0")
    lines.append("forth_words.s:defcode 2dup, twodup, 0")
    lines.append("forth_words.s:defcode 2swap, twoswap, 0")
    lines.append("forth_words.s:defcode ?dup, qdup, 0")
    lines.append("forth_words.s:defcode 1+, incr, 0")
    lines.append("forth_words.s:defcode 1-, decr, 0")
    lines.append("forth_words.s:defcode 4+, incr4, 0")
    lines.append("forth_words.s:defcode 4-, decr4, 0")
    lines.append("forth_words.s:defcode +, add, 0")
    lines.append("forth_words.s:defcode -, sub, 0")
    lines.append("forth_words.s:defcode *, mul, 0")
    lines.append("forth_words.s:defcode /mod, divmod, 0")
    lines.append("forth_words.s:defword /, div, 0")
    lines.append("forth_words.s:defword mod, mod, 0")
    lines.append("forth_words.s:defcode =, equ, 0")
    lines.append("forth_words.s:defcode <>, nequ, 0")
    lines.append("forth_words.s:defcode <, lt, 0")
    lines.append("forth_words.s:defcode >, gt, 0")
    lines.append("forth_words.s:defcode <=, le, 0")
    lines.append("forth_words.s:defcode >=, ge, 0")
    lines.append("forth_words.s:defcode 0=, zequ, 0")
    lines.append("forth_words.s:defcode 0<>, znequ, 0")
    lines.append("forth_words.s:defcode 0<, zlt, 0")
    lines.append("forth_words.s:defcode 0>, zgt, 0")
    lines.append("forth_words.s:defcode 0<=, zle, 0")
    lines.append("forth_words.s:defcode 0>=, zge, 0")
    lines.append("forth_words.s:defcode and, and, 0")
    lines.append("forth_words.s:defcode or, or, 0")
    lines.append("forth_words.s:defcode xor, xor, 0")
    lines.append("forth_words.s:defcode invert, invert, 0")
    lines.append("forth_words.s:defcode !, store, 0")
    lines.append("forth_words.s:defcode @, fetch, 0")
    lines.append("forth_words.s:defcode +!, addstore, 0")
    lines.append("forth_words.s:defcode -!, substore, 0")
    lines.append("forth_words.s:defcode c!, storebyte, 0")
    lines.append("forth_words.s:defcode c@, fetchbyte, 0")
    lines.append("forth_words.s:defcode w!, storeword, 0")
    lines.append("forth_words.s:defcode w@, fetchword, 0")
    lines.append("forth_words.s:defcode c@c!, ccopy, 0")
    lines.append("forth_words.s:defcode cmove, cmove, 0")
    lines.append("forth_words.s:defcode >r, tor, 0")
    lines.append("forth_words.s:defcode r>, fromr, 0")
    lines.append("forth_words.s:defcode rsp@, rspfetch, 0")
    lines.append("forth_words.s:defcode rsp!, rspstore, 0")
    lines.append("forth_words.s:defcode rdrop, rdrop, 0")
    lines.append("forth_words.s:defcode branch, branch, 0")
    lines.append("forth_words.s:defcode 0branch, zbranch, 0")
    lines.append("forth_words.s:defcode dsp@, dspfetch, 0")
    lines.append("forth_words.s:defcode dsp!, dspstore, 0")
    lines.append("forth_words.s:defcode shl, shl, 0")
    lines.append("forth_words.s:defcode shr, shr, 0")
    lines.append("forth_words.s:defword n_byte, n_byte, 0")
    lines.append("forth_words.s:defcode execute, execute, 0")
    lines.append("idt.fth:defcode set_idt, set_idt, 0")
    lines.append("idt.fth:defcode set_idtr, set_idtr, 0")
    lines.append("irq.fth:defcode irq_init, irq_init, 0")
    lines.append("irq.fth:defcode isr_info, isr_info, 0")
    lines.append("kernel_kbd.fth:defvar key_status, key_status, 0, 0")
    lines.append("kernel_test.fth:defvar tic_count, tic_count, 0, 0")
    lines.append("kernel_test.fth:defcode test_irq, test_irq, 0")
    lines.append("kernel_video.fth:defconst screen, screen, 0, 0xB8000")
    lines.append("kernel_video.fth:defvar cursor_pos_x, cursor_pos_x, 0 , 0")
    lines.append("kernel_video.fth:defvar cursor_pos_y, cursor_pos_y, 0 , 0")
    lines.append("kernel_video.fth:defvar screen_color, screen_color, 0, 0x0f00")
    lines.append("kernel_video.fth:defcode ink, ink, 0")
    lines.append("kernel_video.fth:defcode bg, bg, 0")
    lines.append("kernel_video.fth:defcode c>cw, char_to_charword, 0")
    lines.append("kernel_words.fth:defcode outb, outb, 0")
    lines.append("kernel_words.fth:defcode inb, inb, 0")
    lines.append("idt.fth:: idt_set_table, idt_set_table, 0")
    lines.append("idt.fth:: idt_init, idt_init, 0")
    lines.append("irq.fth:: irq_handler, irq_handler, 0")
    lines.append("irq.fth:: register_isr_handler, register_isr_handler, 0")
    lines.append("kernel.fth:: main_kernel, main_kernel, 0")
    lines.append("kernel_kbd.fth:: kbd_flags, kbd_flags, 0")
    lines.append("kernel_kbd.fth:: kbd_buffer_full, kbd_buffer_full, 0")
    lines.append("kernel_kbd.fth:: kbd_scancode_now, kbd_scancode_now, 0")
    lines.append("kernel_kbd.fth:: kbd_scancode, kbd_scancode, 0")
    lines.append("kernel_kbd.fth:: _tx_key_status, _tx_key_status, 0")
    lines.append("kernel_kbd.fth:: _update_key_status, _update_key_status, 0")
    lines.append("kernel_kbd.fth:: _key_down?, _key_down, 0")
    lines.append("kernel_kbd.fth:: sc>c, scancode2char, 0")
    lines.append("kernel_kbd.fth:: getchar, getchar, 0")
    lines.append("kernel_pit.fth:: pit_init, pit_init, 0")
    lines.append("kernel_test.fth:: print_scancode, print_scancode, 0")
    lines.append("kernel_test.fth:: print_tic, print_tic, 0")
    lines.append("kernel_test.fth:: print_scancodes, print_scancodes, 0")
    lines.append("kernel_test.fth:: print_interrupt, print_interrupt, 0")
    lines.append("kernel_test.fth:: print_idtentry, print_idtentry, 0")
    lines.append("kernel_test.fth:: div_by_zero, div_by_zero, 0")
    lines.append("kernel_test.fth:: print_hello, print_hello, 0")
    lines.append("kernel_test.fth:: test_invoke, test_invoke, 0")
    lines.append("kernel_test.fth:: main_test, main_test, 0")
    lines.append("kernel_video.fth:: cursor_pos_rel, cursor_pos_rel, 0")
    lines.append("kernel_video.fth:: cursor_pos, cursor_pos, 0")
    lines.append("kernel_video.fth:: at_hw, at_hw, 0")
    lines.append("kernel_video.fth:: atx, atx, 0")
    lines.append("kernel_video.fth:: bright, bright, 0")
    lines.append("kernel_video.fth:: screen_scroll, screen_scroll, 0")
    lines.append("kernel_video.fth:: _clean_last_line, _clean_last_line, 0")
    lines.append("kernel_video.fth:: screen_scroll_, screen_scroll_, 0")
    lines.append("kernel_video.fth:: cursor_forward, cursor_forward, 0")
    lines.append("kernel_video.fth:: emitcw, emitcw, 0")
    lines.append("kernel_video.fth:: emit, emit, 0")
    lines.append("kernel_video.fth:: printcstring, printcstring, 0")
    lines.append("kernel_video.fth:: clear, clear, 0")
    lines.append("kernel_video.fth:: cr, cr, 0")
    lines.append("kernel_video.fth:: spc, spc, 0")
    lines.append("kernel_video.fth:: tab, tab, 0")
    lines.append("kernel_video.fth:: intprint, intprint, 0")
    lines.append("kernel_video.fth:: hexprint, hexprint, 0")
    lines.append("kernel_words.fth:: lo, lo, 0")
    lines.append("kernel_words.fth:: hi, hi, 0")
    lines.append("test.fth:: test_add, test_add, 0")
    lines.append("test.fth:: test_invoke, test_invoke, 0")
    lines.append("test.fth:: main, main, 0")

    for line in lines:
        parts = line.split()
        parts = ''.join(parts[1:]).split(',')
        key = parts[0]
        val = parts[1]
        dct[key] = val
    return dct

def get_literals():
    '''
    function: get_literals
      Return a list with the names of the %defines and labels found in assembly
      or forth files. It is used to translate literals words.
    '''
    # Get 'define' literals
    #defs = commands.getoutput("grep '^%define ' *.s *.fth").splitlines()
    defs = []
    defs.append("irq.fth:%define _irqmsg irqmsg")
    defs.append("irq.fth:%define _irqmsg2 irqmsg2")
    defs.append("kernel_kbd.fth:%define keymap keymap")
    defs.append("kernel_kbd.fth:%define _key_stat_caps 0x01")
    defs.append("kernel_kbd.fth:%define _key_stat_shift 0x02")
    defs.append("kernel_test.fth:%define _invoke_addr print_hello")
    defs.append("test.fth:%define _invoke_addr invoke_addr")
    defs = [x.split()[1] for x in defs]
    # Get labels
    #labels = commands.getoutput(
    #        "grep '^[:space:]*[A-Za-z0-9_]\+:' *.s *.fth").splitlines()
    labels = []
    labels.append("boot.s:mboot:")
    labels.append("boot.s:start:")
    labels.append("forth_core.s:DOCOL:")
    labels.append("gdt.s:gdtable:")
    labels.append("gdt.s:gdt_pointer:")
    labels.append("gdt.s:gdt_flush:")
    labels.append("gdt.s:flush2:")
    labels.append("kbd_map.s:keymap:")
    labels.append("idt.fth:isr_routine: interrupt_routine _isr_routine")
    labels.append("idt.fth:irq_routine: interrupt_routine _irq_routine")
    labels.append("idt.fth:_isr_routine:")
    labels.append("idt.fth:_irq_routine:")
    labels.append("idt.fth:isr0:       isr_wo_error 0      ;  Division By Zero Exception, No")
    labels.append("idt.fth:isr1:       isr_wo_error 1      ;  Debug Exception, No")
    labels.append("idt.fth:isr2:       isr_wo_error 2      ;  Non Maskable Interrupt Exception, No")
    labels.append("idt.fth:isr3:       isr_wo_error 3      ;  Breakpoint Exception, No")
    labels.append("idt.fth:isr4:       isr_wo_error 4      ;  Into Detected Overflow Exception, No")
    labels.append("idt.fth:isr5:       isr_wo_error 5      ;  Out of Bounds Exception, No")
    labels.append("idt.fth:isr6:       isr_wo_error 6      ;  Invalid Opcode Exception, No")
    labels.append("idt.fth:isr7:       isr_wo_error 7      ;  No Coprocessor Exception, No")
    labels.append("idt.fth:isr8:       isr_with_error 8    ;  Double Fault Exception, yes")
    labels.append("idt.fth:isr9:       isr_wo_error 9      ;  Coprocessor Segment Overrun Exception, No")
    labels.append("idt.fth:isr10:      isr_with_error 10   ;  Bad TSS Exception, yes")
    labels.append("idt.fth:isr11:      isr_with_error 11   ;  Segment Not Present Exception, yes")
    labels.append("idt.fth:isr12:      isr_with_error 12   ;  Stack Fault Exception, yes")
    labels.append("idt.fth:isr13:      isr_with_error 13   ;  General Protection Fault Exception, yes")
    labels.append("idt.fth:isr14:      isr_with_error 14   ;  Page Fault Exception, yes")
    labels.append("idt.fth:isr15:      isr_wo_error 15     ;  Unknown Interrupt Exception, No")
    labels.append("idt.fth:isr16:      isr_wo_error 16     ;  Coprocessor Fault Exception, No")
    labels.append("idt.fth:isr17:      isr_wo_error 17     ;  Alignment Check Exception (486+), No")
    labels.append("idt.fth:isr18:      isr_wo_error 18     ;  Machine Check Exception (Pentium/586+), No")
    labels.append("idt.fth:isr19:      isr_wo_error 19     ; Reserved")
    labels.append("idt.fth:isr20:      isr_wo_error 20     ; Reserved")
    labels.append("idt.fth:isr21:      isr_wo_error 21     ; Reserved")
    labels.append("idt.fth:isr22:      isr_wo_error 22     ; Reserved")
    labels.append("idt.fth:isr23:      isr_wo_error 23     ; Reserved")
    labels.append("idt.fth:isr24:      isr_wo_error 24     ; Reserved")
    labels.append("idt.fth:isr25:      isr_wo_error 25     ; Reserved")
    labels.append("idt.fth:isr26:      isr_wo_error 26     ; Reserved")
    labels.append("idt.fth:isr27:      isr_wo_error 27     ; Reserved")
    labels.append("idt.fth:isr28:      isr_wo_error 28     ; Reserved")
    labels.append("idt.fth:isr29:      isr_wo_error 29     ; Reserved")
    labels.append("idt.fth:isr30:      isr_wo_error 30     ; Reserved")
    labels.append("idt.fth:isr31:      isr_wo_error 31     ; Reserved")
    labels.append("idt.fth:isr32:      irq_wo_error 32     ; PIT timer")
    labels.append("idt.fth:isr33:      irq_wo_error 33     ; Keyboard")
    labels.append("idt.fth:isr34:      irq_wo_error 34     ; PIT beep")
    labels.append("idt.fth:isr35:      irq_wo_error 35")
    labels.append("idt.fth:isr36:      irq_wo_error 36")
    labels.append("idt.fth:isr37:      irq_wo_error 37")
    labels.append("idt.fth:isr38:      irq_wo_error 38")
    labels.append("idt.fth:isr39:      irq_wo_error 39")
    labels.append("idt.fth:isr40:      irq_wo_error 40")
    labels.append("idt.fth:isr41:      irq_wo_error 41")
    labels.append("idt.fth:isr42:      irq_wo_error 42")
    labels.append("idt.fth:isr43:      irq_wo_error 43")
    labels.append("idt.fth:isr44:      irq_wo_error 44")
    labels.append("idt.fth:isr45:      irq_wo_error 45")
    labels.append("idt.fth:isr46:      irq_wo_error 46")
    labels.append("idt.fth:isr47:      irq_wo_error 47")
    labels.append("idt.fth:idt_pointer:")
    labels.append("idt.fth:idtable:  times 48 dq 0")
    labels.append("irq.fth:isr_table: times 48 dq 0")
    labels.append("kernel.fth:main:")
    labels.append("kernel.fth:cold_start:")
    labels.append("kernel.fth:return_stack:")
    labels.append("kernel.fth:return_stack_top:")
    labels.append('kernel_test.fth:hello:      db "hello, world", 0"')
    labels.append('kernel_test.fth:fault:      db "A fault happened", 0"')
    labels.append('kernel_test.fth:tic_msg:    db "The clock tic"s, 0"')
    labels.append("test.fth:_start:")
    labels.append("test.fth:cold_start:")
    labels.append("test.fth:return_stack:")
    labels.append("test.fth:return_stack_top:")
    labels.append("test.fth:_invoke_addr: dd test_add")

    labels = [x.split(':')[1] for x in labels]
    return defs + labels

def get_macros():
    '''
    function: get_macros
       Returns a list with the name of all the macros found in assembly or
       forth files. It is used to translate macro words.
    '''
    lst = []
    lst.append("next")
    lst.append("pushrsp")
    lst.append("poprsp")
    lst.append("defword")
    lst.append("defcode")
    lst.append("defvar")
    lst.append("defconst")
    lst.append("litn")
    lst.append("branch_")
    lst.append("zbranch_")
    lst.append("if")
    lst.append("else")
    lst.append("then")
    lst.append("do")
    lst.append("loop")
    lst.append("begin")
    lst.append("until")
    lst.append("while")
    lst.append("repeat")
    lst.append("leave")
    lst.append("call_forth")
    lst.append("gdt_entry")
    lst.append("isr_wo_error")
    lst.append("isr_with_error")
    lst.append("irq_wo_error")
    lst.append("interrupt_routine")

    return lst
    #return commands.getoutput(
    #        "grep -r '%macro' *.s *.fth| awk '{print $2}'").split()

MACROS = get_macros()
SYMBOLS = get_symbols()
LITERALS = get_literals()

def main():
    '''
    function: main
      Translate forth code in a file to nasm assembler and stores in other
      file.
    '''
    opts, args = parser.parse_args()
    fin = open(opts.finname)
    fout = open(opts.foutname, 'w')
    copy_lines(fin, fout)


if __name__ == '__main__' :
    main()
