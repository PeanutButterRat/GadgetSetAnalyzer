[GSA]: https://github.com/michaelbrownuc/GadgetSetAnalyzer
[RopSched]: https://github.com/PeanutButterRat/ropsched
[Original Paper]: https://www.usenix.org/system/files/cset19-paper_brown.pdf
[Updated Paper]: https://arxiv.org/pdf/1902.10880.pdf


# GadgetSetAnalyzer

**GadgetSetAnalyzer** (GSA) is security-oriented static binary analysis tool for comparing the quantity and quality of code reuse gadgets in program variants. This project is a slimmed-down version of the original tool published by **Micheal D. Brown** and **Sontosh Pande** from Georgia Institute of Technology which can be found [here][GSA].


## Changes
This version of GSA has most of it's functionality stripped away to make it easier to modify for my purposes. All of the original metrics besides the gadget count and quality comparisons have been removed from the codebase. It does, however, offer additional AArch64 support that is not present in the original tool at the time of writing, which only supports x86.


## Usage
This version of GSA isn't meant to be run directly. Instead, you should should refer to its parent repository, [RopSched][RopSched].

**RopSched** is a fork of LLVM that uses a scheduling-based approach to reduce the number of usable gadgets in a binary. RopSched uses this watered-down version of GSA as a benchmarking tool to evaluate it's performance on Rust-based projects. Please see [RopSched][RopSched] for usage instructions, or the original [GadgetSetAnalyzer][GSA] for a stand-alone tool.


## Useful References
 1. [GadetSetAnalyzer][GSA]: the original tool with additional features.
 2. [Original Paper (2019)][Original Paper]: the original paper published alongside the tool.
 3. [Updated Paper (2019)][Updated Paper]: a revision of the first publication that expands on the work presented in the original with some additional metrics.
