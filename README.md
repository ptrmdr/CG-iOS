# CGiOS: Call Graphs in iOS Apps

A collection of ghidra scripts to extract a call graph from iOS binaries.
The scripts currently depend on [tinkerpop](https://github.com/apache/tinkerpop) graphs and ghidra11.1

## Structure of the project
The project is divided into to two ghidra scripts.
In first script `ExtractMachOTypeHierarchy` the type hierarchy is extracted and analysed
and in the second script `ReconstructAppleIosCFG` the call graph is reconstructed from the binary.

## Install and run the project
Ghidra is set as a maven dependency in `pom.xml` 
but to make this work the ghidra jar has to be build and added to the local maven repository.

[Ghidra releases](https://github.com/NationalSecurityAgency/ghidra/releases)

[Single Ghidra JAR](https://ghidra-sre.org/InstallationGuide.html#RunJar)

[How to add a jar to your local maven repo](https://maven.apache.org/guides/mini/guide-3rd-party-jars-local.html)

In a second step you have to setup a ghidra project and reference that project in the `Main.java` at:
```java
a.getOptions().setRunScriptsNoImport(true, "DispatchApp.debug.dylib");      //binary to process

a.processLocal(
    "~/Documents/ghidraProjects/helloworld_ios",    //directory of project
    "helloworld_ios",                               //project name
    "/DispatchApp.app/",                            //directory inside project
    null
);
```