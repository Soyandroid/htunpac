# Htunpac
Code to "unpac" htpac protected games, executable only. Since htpac can be configured with a variety of parameters which
might result in differently packed games, the code in this repository is targetted specificlly towards a specific game
and version, only. Other games will likely not work and require further changes accordingly.

Note: This version has been used and tested on Beatmania IIDX Empress, only. There is another version that was used
for IIDX Sirius which requires to either rollback to the commit 7a0b4d006d69b6039ef96ef026bef4379c6133f5 or checking
out the branch `sirius` of the repository.

For details, see the [dumping instructions readme file](kernal32/dumping-instructions.md).

This way of unpacking is rather inflexible and involves a lot of tweaking for different games and situations.
Still, it can serve as a good reference or alternative solution to the more flexible and sophisticated way provided by
[iatrepair](https://dev.s-ul.eu/djhackers/iatrepair).

Further probably useful references and tools that were used:
* [PE format](doc/PE Format.pdf)
* [Explorer Suite](tools/explorersuite.exe): View and modify PE files
* [Import REConstructor](tools/Bin_ImpREC_2011-7-16_8.11_ImpREC_1.7e.rar)

## Building
You need mingw installed, basically same setup as bemanitools.

Just run `make` in the project's root folder to build.