# Readme:
## Directory Structure
This contanins two directories driver and user programs for test
**1.** The **driver** directory contains the driver **btplus.c** and the header file **btplus.h** it uses and **makefile** .
**2.** The **example test user programs** directory contains the user program files **part1_1.c** and **part1_2.c**

### To build it:
**1.** First load the linux kernel 6.1.4 .
**2.** Compile the driver using Makefile in driver folder and the load the driver as **sudo insmod btplus.ko**.
**3.** Then Compile the user programs and run them to see the outputs.

### User Programs:
**1.** The user program **part1_1.c** contains test for moving a VMA to an new location by giving a new address as input to the driver the new location should have enough memory space and should be empty else the driver will not move the VMA to that address and after that the old VMA is deleted hence If try to access old location after this then it will raise seg fault.



**2.** The user program **part1_2.c** contains test for moving VMA to a hole next to it which has sufficient space to hold this VMA after this operation also the old VMA gets deleted and access to it will raise seg fault.
