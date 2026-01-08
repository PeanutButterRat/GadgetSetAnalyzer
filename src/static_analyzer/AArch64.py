from .GadgetSet import GadgetSet
from enum import Enum, auto


class GadgetType(Enum):
    ROP = auto()
    COP = auto()
    JOP = auto()


class ArmInstruction(object):
    def __init__(self, instruction):
        self.raw = instruction
        self.operands = []

        if " " not in instruction:
            self.opcode = instruction
        else:
            self.opcode = self.opcode = instruction[:instruction.find(" ")]

            operands = self.raw[len(self.opcode):].strip()
            operand = ""
            inside_brackets = False

            for ch in operands:
                if ch == "[":
                    inside_brackets = True
                    operand += ch
                elif  ch == "]":
                    inside_brackets = False
                    operand += ch
                elif ch == "," and not inside_brackets:
                    self.operands.append(operand.strip())
                    operand = ""
                else:
                    operand += ch

            if operand.strip():
                self.operands.append(operand.strip())

    def is_data_move(self):
        return self.opcode in {"mov", "uxtb", "uxth", "uxtw", "sxtb", "sxth", "sxtw", "movz"}

    def is_arithmetic(self):
        return self.opcode in {
            "adc", "adcs", "add", "adds", "adr", "adrp", "madd", "mneg", "msub", "mul", "neg",
            "negs", "ngc", "ngcs", "sbc", "sbcs", "sdiv", "smaddl", "smnegl", "smsubl", "smulh",
            "smull", "sub", "subs", "udiv", "umaddl", "umnegl", "umsubl", "umulh", "umull"
        }
    
    def is_bitwise_operation(self):
        return self.opcode in {
            "bfi", "bfxil", "cls", "clz", "extr", "rbit", "rev", "rev16", "rev32", "sxtw",
            "sbfiz", "ubfiz", "sbfx", "ubfx", "sxtb", "sxth", "uxtb", "uxth"
        }

    def is_shift_or_rotate(self):
        # For simplicity, this doesn't check arithmetic instructions for shifts as well.
        return self.opcode in {"lsl", "lsr", "asr", "ror"}

    def is_data_store(self):
        return self.opcode.startswith("st")

    def is_data_load(self):
        return self.opcode.startswith("ld")

    def is_conditional_data_move(self):
        # Conditional instructions that set another register's value based on another register's value (value is register dependent).
        return self.opcode in {"csel", "cinc", "csinc", "cinv", "csinv", "cneg", "csneg"}

    def is_conditional_jump(self):
        return self.opcode.startswith("b.") or self.opcode in {"cbz", "cbnz", "tbz", "tbnz"}

    def is_conditional_set(self):
        # Conditional instructions that set another register's value to some constant (value is register independent).
        return self.opcode in {"cset", "csetm"}

    def get_destination_register(self):
        if len(self.operands) > 0:
            rd = self.operands[0]

            if (rd and rd[0] in ["w", "x"] and rd[1:].isnumeric()) or rd == "sp":
                return rd

        return None

    def __repr__(self):
        return f"{self.opcode} {', '.join(self.operands)}"

    def __str__(self):
        return self.raw

class ArmGadget(object):
    def __init__(self, raw_gadget):
        instruction_string = raw_gadget[raw_gadget.find(":") + 2:]

        self.instructions = []

        for instruction in instruction_string.split(" ; "):
            self.instructions.append(ArmInstruction(instruction))

        self.score = 0.0
        self.gpi = self.instructions[-1].opcode  # Gadget-producing instruction
        self.rd = self.instructions[0].get_destination_register()  # Gadget's value destination register.
        self.raw = ", ".join(str(instruction) for instruction in self.instructions)

        # General scoring.
        self.check_conditional_operations()
        self.check_register_operations()
        self.check_memory_writes()

        # Category-specific scoring.
        if self.gpi == "ret":
            self.gadget_type = GadgetType.ROP
            self.check_stack_pointer_operations()
        elif self.gpi in ["br", "b"]:
            self.gadget_type = GadgetType.JOP
        elif self.gpi == "blr":
            self.gadget_type = GadgetType.COP
        else:
            raise RuntimeError(f"unknown gadget-producing instruction encoutered: {self.gpi}")

    def is_rop_gadget(self):
        return self.gadget_type == GadgetType.ROP

    def is_jop_gadget(self):
        return self.gadget_type == GadgetType.JOP

    def is_cop_gadget(self):
        return self.gadget_type == GadgetType.COP

    def check_conditional_operations(self):
        for instruction in self.instructions[:-1]:
            if instruction.is_conditional_jump():
                self.score += 3.0
            elif instruction.is_conditional_data_move():
                self.score += 2.0
            elif instruction.is_conditional_set():
                self.score += 1.0

    def check_register_operations(self):
        for instruction in self.instructions[1:-1]:  # Don't include first instruction because it will always modify rd by definition.
            destination_register = instruction.get_destination_register()
            instruction_modifies_rd = destination_register == self.rd and None not in [destination_register, self.rd]

            if instruction.is_shift_or_rotate():
                self.score += 1.5 if instruction_modifies_rd else 1.0

            # There probably more instructions that modify registers, but this should cover most opcodes. 
            elif instruction.is_arithmetic() or instruction.is_data_move() or instruction.is_bitwise_operation():
                self.score += 1.0 if instruction_modifies_rd else 0.5

    def check_memory_writes(self):
        for instruction in self.instructions[:-1]:
            if instruction.is_data_store():
                self.score += 1.0

    def check_stack_pointer_operations(self):
        for instruction in self.instructions[:-1]:
            if instruction.get_destination_register() != "sp":
                continue
            elif instruction.is_data_move() or instruction.is_data_load() or instruction.is_conditional_data_move():
                self.score += 4.0
            elif instruction.is_shift_or_rotate():
                self.score += 3.0
            else:
                self.score += 2.0

            # Note: this is missing one scoring critiera: (+1.0) Gadget has intermediate instruction that pops stack value into RSP/ESP
            # This is because there is no "pop" instruction in Aarch64, any pop would have to be implemented with a series of
            # other instructions.

    def is_gpi_only(self):
        return len(self.instructions) == 1

    def __repr__(self):
        return f"ArmGadget({' ; '.join(str(instr) for instr in self.instructions)}) -> {self.score}"

    def __eq__(self, other):
        return self.raw == other.raw

    def __hash__(self):
        return hash(self.raw)


class ArmGadgetSet(GadgetSet):
    def __init__(self, name, filepath):
        self.unique_gadgets = set()
        super().__init__(name, filepath)

    def parse_gadgets(self, filepath, output):
        lines = output.split("\n")

        for line in lines:
            if line == "Gadgets information" or \
                    line == "============================================================" or \
                    line == "" or \
                    line.startswith("Unique gadgets found"):
                continue
            elif line == "[Error] Binary format not supported":
                raise RuntimeError(f"GSA cannot analyze this type of file ({filepath})")
            else:
                self.allGadgets.append(ArmGadget(line))

    def analyze_gadget(self, gadget):
        if not self.is_unique(gadget) or gadget.is_gpi_only():
            return

        self.unique_gadgets.add(gadget)

        if gadget.is_rop_gadget():
            self.ROPGadgets.append(gadget)
            self.total_ROP_score += gadget.score
        elif gadget.is_jop_gadget():
            self.JOPGadgets.append(gadget)
            self.total_JOP_score += gadget.score
        else:  # gadget.is_cop_gadget():
            self.COPGadgets.append(gadget)
            self.total_COP_score += gadget.score

    def is_unique(self, gadget):
        return gadget not in self.unique_gadgets
