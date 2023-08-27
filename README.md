# Pisces
This is a prototype of the private and compliable cryptocurrency exchange scheme in Java.
## Description
Pisces is a secure design of the private and compliable cryptocurrency exchange system. The system includes two entities: the user and the platform. It achieves four main functions to enable the user to join the system, deposit coins to the platform, exchange coins with the platform, and withdraw coins from the platform to the blockchain.

The artifact implements all four procedures. For each procedure, the user sub-procedure interacts with the platform sub-procedure locally via memory communication, so that we can test the efficiency and practality via focusing on testing the computation time cost and communication size, and excluding communication time cost. The source code od Pisce is /src directory. We also provide the jar package for test purpose. The shown results in testlog.log is produced by running jar package on on MacBook Air (1.6GHz Dual-Core Intel Core i5, 16GB memory). The provided instructions in the folowing  should work for both MacOS and Linux, but the results may vary a bit depending on the computation powder.

## Installation
Download the full repository.

### Requirements
- MacOS or Linux (not necessary, instructions only apply to the two systems)
- JDK 17 or later
- Maven 3.8.1 or later (not necessary for the test)
- GMP library and MCL library

### Install GMP library on Linux and MacOS
we recommend you follow the [gmp installment methods](https://github.com/alibaba-edu/mpc4j/tree/main/mpc4j-native-tool/doc) according to your os. 

### Install mcl library and wrap for our use
There are good instructions for [compiling mcl library and wrap to java on Linuc or MacOS](https://github.com/cryptimeleon/mclwrap#compiling-mcl-on-linux-or-macos). The details are as follows:

- download the file [install_fast_mcljava_linux_mac.sh](https://github.com/cryptimeleon/mclwrap/blob/develop/scripts/install_fast_mcljava_linux_mac.sh)
- execute the command to compile mcl. I assume your current directory is where the file was downloaded. Please install JDK first and get your java installment directory.

```
./install_fast_mcljava_linux_mac.sh $JAVA_HOME/include  # $JAVA\_HOME is the Java installment directory
```
If you do not have execution permission, please give yourself permission first via 
```
chmod 777 ./install_fast_mcljava_linux_mac.sh
```

With JDK, GMP, and MCL installed, I'm sure you are ready to test.

## Test
- Run Pisces to test the computation cost and communication size.

Pisces source code has been packaged to Pisces-1.0-jar-with-dependencies.jar in the repository. So, you need to download the file and go to the download directory, and run:
```
java -jar Pisces-1.0-jar-with-dependencies.jar
```
If your experiment is similar to MacBook Air (1.6GHz Dual-Core Intel Core i5, 16GB memory), the results should be similar to those in testlog.log, which is also shown in the paper.
 
- run UACS implementation to compare with our implementation.

We follow their design logic and adjust according to our needed zero-knowledge proofs. Both Pisces and uacs can be seen as applications of anonymous credential. This is [UACS's original implementaion](https://github.com/cryptimeleon/uacs-incentive-system). We package it into the file uacs-1.0-SNAPSHOT-jar-with-dependencies.jar in the repository. You can download it and run it to test the computation cost in your system with the command:
```
java -jar uacs-1.0-SNAPSHOT-jar-with-dependencies.jar
```
Our test results of uacs are shown in uacstestlog.log under the same environment as the Pisces test.

## Acknowledgement
Portions of the project have been copied from project [acs-incentive-system](https://github.com/cryptimeleon/uacs-incentive-system) and are copyrighted by [Jan Bobolz](https://github.com/JanBobolz) and [feidens](https://github.com/feidens)  under the terms of the Apache-2.0 license.
