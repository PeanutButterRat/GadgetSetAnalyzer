"""
Gadget Set Class
"""

# Standard Library Imports
import subprocess
from pathlib import Path
import os

# Third Party Imports
import angr

# Local Imports
from static_analyzer.Gadget import Gadget
from static_analyzer.Instruction import Instruction


class GadgetSet(object):
    """
    The GadgetSet class is initialized from a binary file and records information about the utility and availability
    of gadgets present in the binary's encoding.
    """

    def __init__(self, name, filepath):
        """
        GadgetSet constructor
        :param str name: Name for the gadget set
        :param str filepath: Path to the file on disk.
        """

        # Determine how many binaries will make up the gadget set
        self.binaries = []
        self.binary_path = Path(os.path.expanduser(filepath))
        if not self.binary_path.exists():
            raise FileNotFoundError(filepath)
        elif os.path.isfile(self.binary_path):
            self.binaries.append(filepath)
        elif os.path.isdir(self.binary_path):
            # Walk the directory and add all files to list of binaries.
            for fp in os.listdir(self.binary_path):
                full_fp = os.path.join(self.binary_path, fp)
                if os.path.isfile(full_fp):
                    self.binaries.append(full_fp)

        self.name = name
        self.cnt_rejected = 0
        self.cnt_duplicate = 0

        # Initialize functional gadget type lists
        self.allGadgets = []
        self.ROPGadgets = []
        self.JOPGadgets = []
        self.COPGadgets = []

        # Initialize special purpose gadget type lists
        self.SyscallGadgets = []
        self.JOPDispatchers = []
        self.JOPDataLoaders = []
        self.JOPInitializers = []
        self.JOPTrampolines = []
        self.COPDispatchers = []
        self.COPStrongTrampolines = []
        self.COPIntrastackPivots = []
        self.COPDataLoaders = []
        self.COPInitializers = []

        # Initialize total and average quality scores
        self.total_ROP_score = 0.0
        self.total_JOP_score = 0.0
        self.total_COP_score = 0.0
        self.averageROPQuality = 0.0
        self.averageJOPQuality = 0.0
        self.averageCOPQuality = 0.0
        self.average_functional_quality = 0.0

        # Run ROPgadget to populate total gadget set (includes duplicates and multi-branch gadgets)
        for fp in self.binaries:
            self.parse_gadgets(fp, GadgetSet.runROPgadget(fp, "--all --multibr"))

        # Reject unusable gadgets, sort gadgets into their appropriate category sets, score gadgets
        for gadget in self.allGadgets:
            self.analyze_gadget(gadget)

        # Calculate gadget set counts / quality metrics
        self.total_sp_gadgets = 0
        self.total_sp_types = 0
        if len(self.SyscallGadgets) > 0:
            self.total_sp_types += 1
            self.total_sp_gadgets += len(self.SyscallGadgets)
        if len(self.JOPInitializers) > 0:
            self.total_sp_types += 1
            self.total_sp_gadgets += len(self.JOPInitializers)
        if len(self.JOPTrampolines) > 0:
            self.total_sp_types += 1
            self.total_sp_gadgets += len(self.JOPTrampolines)
        if len(self.JOPDispatchers) > 0:
            self.total_sp_types += 1
            self.total_sp_gadgets += len(self.JOPDispatchers)
        if len(self.JOPDataLoaders) > 0:
            self.total_sp_types += 1
            self.total_sp_gadgets += len(self.JOPDataLoaders)
        if len(self.COPDataLoaders) > 0:
            self.total_sp_types += 1
            self.total_sp_gadgets += len(self.COPDataLoaders)
        if len(self.COPDispatchers) > 0:
            self.total_sp_types += 1
            self.total_sp_gadgets += len(self.COPDispatchers)
        if len(self.COPInitializers) > 0:
            self.total_sp_types += 1
            self.total_sp_gadgets += len(self.COPInitializers)
        if len(self.COPStrongTrampolines) > 0:
            self.total_sp_types += 1
            self.total_sp_gadgets += len(self.COPStrongTrampolines)
        if len(self.COPIntrastackPivots) > 0:
            self.total_sp_types += 1
            self.total_sp_gadgets += len(self.COPIntrastackPivots)

        self.total_functional_gadgets = len(self.ROPGadgets) + len(self.JOPGadgets) + len(self.COPGadgets)
        self.total_unique_gadgets = self.total_sp_gadgets + self.total_functional_gadgets

        self.total_score = self.total_ROP_score + self.total_JOP_score + self.total_COP_score

        if self.total_ROP_score != 0.0:
            self.averageROPQuality = self.total_ROP_score / len(self.ROPGadgets)
        if self.total_JOP_score != 0.0:
            self.averageJOPQuality = self.total_JOP_score / len(self.JOPGadgets)
        if self.total_COP_score != 0.0:
            self.averageCOPQuality = self.total_COP_score / len(self.COPGadgets)
        if self.total_functional_gadgets != 0:
            self.average_functional_quality = self.total_score / self.total_functional_gadgets

    def parse_gadgets(self, filepath, output):
        """
        Converts raw ROPgadget output into a list of Gadget objects.
        :param str output: Plain text output from run of ROPgadget
        :return: List of Gadget objects
        """
        # Iterate through each line and generate a gadget object
        lines = output.split("\n")
        for line in lines:
            # Exclude header/footer information
            if line == "Gadgets information" or \
                    line == "============================================================" or \
                    line == "" or \
                    line.startswith("Unique gadgets found"):
                continue
            elif line == "[Error] Binary format not supported":
                raise RuntimeError(f"GSA cannot analyze this type of file ({filepath})")
            else:
                self.allGadgets.append(Gadget(filepath, line))

    @staticmethod
    def runROPgadget(filepath, flags):
        """
        Runs ROPgadget on the binary at filepath with flags passed.
        :param str filepath: path to binary to analyze
        :param str flags: string containing the flags for execution
        :return: Output from the ROPgadget command as a standard string, None if the data was not collected as expected.
        """

        sub = subprocess.Popen("ROPgadget --binary '" + filepath + "' " + flags, shell=True, stdout=subprocess.PIPE)
        subprocess_return = sub.stdout.read()
        return subprocess_return.decode("utf-8")

    def analyze_gadget(self, gadget):
        """
        Analyzes a gadget to determine its properties
        :param Gadget gadget: gadget to analyze
        :return: None, but modifies GadgetSet collections and Gadget object members
        """

        # Step 1: Eliminate useless gadgets, defined as:
        # 1) Gadgets that consist only of the GPI (SYSCALL gadgets excluded)
        # 2) Gadgets that have a first opcode that is not useful - we assume that the first instruction is part of the
        #    desired operation to be performed (otherwise attacker would just use the shorter version)
        # 3) Gadgets that end in a call/jmp <offset> (ROPgadget should not include these in the first place)
        # 4) Gadgets that create values in segment or extension registers, or are RIP-relative
        # 5) Gadgets ending in returns with offsets that are not byte aligned or greater than 32 bytes
        # 6) Gadgets containing ring-0 instructions / operands
        # 7) Gadgets that contain an intermediate GPI/interrupt (ROPgadget should not include these in the first place)
        # 8) ROP Gadgets that perform non-static assignments to the stack pointer register
        # 9) JOP/COP Gadgets that overwrite the target of and indirect branch GPI
        # 10) JOP/COP gadgets that are RIP-relative
        # 11) Syscall gadgets that end in an interrupt handler that is not 0x80 (ROPgadget should not include these)
        # 12) Gadgets that create value in the first instruction only to overwrite that value before the GPI
        # 13) Gadgets that contain intermediate static calls
        if gadget.is_gpi_only() or gadget.is_useless_op() or gadget.is_invalid_branch() or \
           gadget.creates_unusable_value() or gadget.has_invalid_ret_offset() or gadget.contains_unusable_op() or \
           gadget.contains_intermediate_GPI() or gadget.clobbers_stack_pointer() or \
           gadget.is_rip_relative_indirect_branch() or gadget.clobbers_indirect_target() or \
           gadget.has_invalid_int_handler() or gadget.clobbers_created_value() or gadget.contains_static_call():
            self.cnt_rejected += 1
            return

        # Step 2: Sort the gadget by type. Gadget type determined by GPI and secondary check for S.P. gadgets. Scoring
        #         is only performed for unique functional gadgets.
        gpi = gadget.instructions[len(gadget.instructions)-1].opcode

        if gpi.startswith("ret"):
            if self.add_if_unique(gadget, self.ROPGadgets):
                # Determine score, first checking ROP-specific side constraints
                gadget.check_sp_target_of_operation()  # increase score if stack pointer family is target of certain ops
                gadget.check_contains_leave()          # +2 if gadget contains an intermediate "leave" instruction
                gadget.check_negative_sp_offsets()     # +2 if gadget's cumulative stack pointer offsets are negative

                # Next check general side-constraints
                gadget.check_contains_conditional_op()    # increase score if gadget contains conditional operations
                gadget.check_register_ops()               # increases score for ops on value and bystander register
                gadget.check_memory_writes()              # increases score for each memory write in the gadget

                self.total_ROP_score += gadget.score

        elif gpi.startswith("jmp"):
            if gadget.is_JOP_COP_dispatcher():
                self.add_if_unique(gadget, self.JOPDispatchers)
            elif gadget.is_JOP_COP_dataloader():
                self.add_if_unique(gadget, self.JOPDataLoaders)
            elif gadget.is_JOP_initializer():
                self.add_if_unique(gadget, self.JOPInitializers)
            elif gadget.is_JOP_trampoline():
                self.add_if_unique(gadget, self.JOPTrampolines)
            else:
                if self.add_if_unique(gadget, self.JOPGadgets):
                    # Determine score, first checking JOP-specific side constraints
                    gadget.check_branch_target_of_operation()  # increase score if branch register is target of ops

                    # Next check general side-constraints
                    gadget.check_contains_conditional_op()  # increase score if gadget contains conditional operations
                    gadget.check_register_ops()  # increases score for ops on value and bystander register
                    gadget.check_memory_writes()  # increases score for each memory write in the gadget

                    self.total_JOP_score += gadget.score

        elif gpi.startswith("call"):
            if gadget.is_JOP_COP_dispatcher():
                self.add_if_unique(gadget, self.COPDispatchers)
            elif gadget.is_JOP_COP_dataloader():
                self.add_if_unique(gadget, self.COPDataLoaders)
            elif gadget.is_COP_initializer():
                self.add_if_unique(gadget, self.COPInitializers)
            elif gadget.is_COP_strong_trampoline():
                self.add_if_unique(gadget, self.COPStrongTrampolines)
            elif gadget.is_COP_intrastack_pivot():
                self.add_if_unique(gadget, self.COPIntrastackPivots)
            else:
                if self.add_if_unique(gadget, self.COPGadgets):
                    # Determine score, first checking COP-specific side constraints
                    gadget.check_branch_target_of_operation()  # increase score if branch register is target of ops

                    # Next check general side-constraints
                    gadget.check_contains_conditional_op()  # increase score if gadget contains conditional operations
                    gadget.check_register_ops()  # increases score for ops on value and bystander register
                    gadget.check_memory_writes()  # increases score for each memory write in the gadget

                    self.total_COP_score += gadget.score
        else:
            self.add_if_unique(gadget, self.SyscallGadgets)

    def add_if_unique(self, gadget, collection):
        for rhs in collection:
            if gadget.is_duplicate(rhs):
                self.cnt_duplicate += 1
                return False
        collection.append(gadget)
        return True
