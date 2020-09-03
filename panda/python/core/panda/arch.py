import binascii
from panda.utils import telescope

class PandaArch():
    '''
    Base class with default methods for a PANDA-supported architecture
    '''
    def __init__(self, panda):
        '''
        Initialize a PANDA-supported architecture and hold a handle on the PANDA object
        '''
        self.panda = panda

        self.reg_sp = None # Stack pointer register ID if stored in a register
        self.reg_pc = None # PC register ID if stored in a register
        self.reg_retaddr = None # Return address register ID if stored in a register
        self.wordsize = int(panda.bits/4)

        self.registers = {}
        '''
        Mapping of register names to indices into the appropriate CPUState array
        '''

    def get_reg(self, cpu, reg):
        '''
        Return value in a register by name or index (e.g., "R0" or 0)
        '''
        if isinstance(reg, str):
            if reg not in self.registers.keys():
                raise ValueError(f"Invalid register name {reg}")
            else:
                reg = self.registers[reg]

        return self._get_reg_val(cpu, reg)

    def _get_reg_val(self, cpu, reg):
        '''
        Virtual method. Must be implemented for each architecture to return contents of register specified by reg
        '''
        raise NotImplementedError()

    def get_pc(self, cpu):
        '''
        Default method to get the current program counter
        '''
        if self.reg_pc:
            return self.get_reg(cpu, self.reg_pc)

    def dump_regs(self, cpu):
        '''
        Print (telescoping) each register and its values
        '''
        for (regname, reg) in self.registers.items():
            val = self.get_reg(cpu, reg)
            val = cpu.env_ptr.active_tc.gpr[reg]
            print("{}: 0x{:x}".format(regname, val), end="\t")
            telescope(self.panda, cpu, val)

    def dump_stack(self, cpu, words=8):
        '''
        Print (telescoping) most recent 8 words on the stack (from reg_sp to reg_sp+[words]*word_size)
        '''
        base_reg_s = "SP"
        base_reg_val = self.get_reg(cpu, self.reg_sp)
        for word_idx in range(words):
            val_b = self.panda.virtual_memory_read(cpu, base_reg_val+word_idx*self.word_size, self.word_size)
            val = int.from_bytes(val_b, byteorder='little')
            print("[{}+0x{:0>2x} == 0x{:0<8x}]: 0x{:0<8x}".format(base_reg_s, word_idx*self.word_size, base_reg_val+word_idx*self.word_size, val), end="\t")
            telescope(self.panda, cpu, val)

    def dump_state(self, cpu):
        """
        Print registers and stack
        """
        print("Registers:")
        dump_regs(panda, cpu)
        print("Stack:")
        dump_stack(panda, cpu)

class Arm(PandaArch):
    '''
    Register names and accessors for ARM
    '''
    def __init__(self, panda):
        PandaArch.__init__(self, panda)
        self.reg_sp = 13 # SP
        self.reg_retaddr = 14 # LR
        self.reg_pc = 15 # IP

        regnames = ["R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7",
                    "R8", "R9", "R10", "R11", "R12", "SP", "LR", "IP"]
        registers = {regnames[idx]: idx for idx in range(len(regnames)) }
        """Register array for ARM"""

        self.reg_sp = regnames.index("SP")
        self.reg_retaddr = regnames.index("LR")
        self.reg_pc = regnames.index("IP")

    def _get_reg_val(self, cpu, reg):
        '''
        Return an arm register
        '''
        return cpu.env_ptr.regs[reg]

class Mips:
    '''
    Register names and accessors for MIPS
    '''

    # Registers are:
    '''
    Register Number	Conventional Name	Usage
    $0	        $zero	Hard-wired to 0
    $1	        $at	Reserved for pseudo-instructions
    $2 - $3	        $v0, $v1	Return values from functions
    $4 - $7	        $a0 - $a3	Arguments to functions - not preserved by subprograms
    $8 - $15	$t0 - $t7	Temporary data, not preserved by subprograms
    $16 - $23	$s0 - $s7	Saved registers, preserved by subprograms
    $24 - $25	$t8 - $t9	More temporary registers, not preserved by subprograms
    $26 - $27	$k0 - $k1	Reserved for kernel. Do not use.
    $28	        $gp	Global Area Pointer (base of global data segment)
    $29	        $sp	Stack Pointer
    $30	        $fp	Frame Pointer
    $31	        $ra	Return Address
    '''

    def __init__(self, panda):
        PandaArch.__init__(self, panda)
        regnames = ['zero', 'at', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3',
                    't0', 't1', 't2', 't3', 't4', 't5', 't6', 't7',
                    's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7',
                    't8', 't9', 'k0', 'k1', 'gp', 'sp', 'fp', 'ra']

        self.reg_sp = regnames.index('sp')
        self.reg_retaddr = regnames.index('ra')
        registers = {regnames[idx]: idx for idx in range(len(regnames)) }

    def get_ip(self, cpu):
        '''
        Overloaded function to return the MIPS current program counter
        '''
        return cpu.env_ptr.active_tc.PC

    def _get_reg_val(self, cpu, reg):
        '''
        Return a mips register
        '''
        return cpu.env_ptr.active_tc.gpr

class X86:
    '''
    Register names and accessors for x86
    '''

    def __init__(self, panda):
        PandaArch.__init__(self, panda)
        regnames = ['EAX', 'ECX', 'EDX', 'EBX', 'ESP', 'EBP', 'ESI', 'EDI']
        # XXX Note order is A C D B, because that's how qemu does it . See target/i386/cpu.h

        self.reg_sp = regnames.index('ESP')
        registers = {regnames[idx]: idx for idx in range(len(regnames)) }

    def get_ip(self, cpu):
        '''
        Overloaded function to return the x86 current program counter
        '''
        return cpu.env_ptr.pc

    def _get_reg_val(self, cpu, reg):
        '''
        Return an x86 register
        '''
        return cpu.env_ptr.regs[reg]

class X86_64:
    '''
    Register names and accessors for x86_64
    '''

    def __init__(self, panda):
        PandaArch.__init__(self, panda)
        # The only place I could find the R_ names is in tcg/i386/tcg-target.h:50
        regnames = ['RAX', 'RCX', 'RDX', 'RBX', 'RSP', 'RBP', 'RSI', 'RDI',
                    'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15']
        # XXX Note order is A C D B, because that's how qemu does it

        self.reg_sp = regnames.index('RSP')
        registers = {regnames[idx]: idx for idx in range(len(regnames)) }

    def get_ip(self, cpu):
        '''
        Overloaded function to return the x86 current program counter
        '''
        return cpu.env_ptr.pc

    def _get_reg_val(self, cpu, reg):
        '''
        Return an x86_64 register
        '''
        return cpu.env_ptr.regs[reg]
