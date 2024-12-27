package org.example;

import ghidra.app.util.headless.HeadlessAnalyzer;

import java.io.File;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

public class Main {
    public static void main(String[] args) throws IOException {
        String fileToProcess = "DispatchApp.debug.dylib";//"DVIA-v2";
        String dateTimeString = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        File scriptLog = new File(String.format("./logs/%s_%s.log", fileToProcess, dateTimeString));
        HeadlessAnalyzer a = HeadlessAnalyzer.getLoggableInstance(null, scriptLog, true);
        a.reset();

        a.getOptions().enableAnalysis(true);
        a.getOptions().enableReadOnlyProcessing(true);
        a.getOptions().setRunScriptsNoImport(true, fileToProcess);

        File localScripts = new File("./src/main/java");
        List<String> scriptDirs = List.of(localScripts.getAbsolutePath());
        a.getOptions().setScriptDirectories(scriptDirs);

        List<String> postScripts = List.of(
                "org.example.ExtractMachOTypeHierarchy",
                "org.example.ReconstructAppleIosCFG"
        );
        a.getOptions().setPostScripts(postScripts);

        Instant start = Instant.now();
        a.processLocal(
                "../../Documents/ghidraProjects/helloworld_ios",
                "helloworld_ios",
                "/DispatchApp.app/",//"/Telegram.ipa/Payload/Telegram.app/",
                null
        );
        Instant finish = Instant.now();
        long timeElapsed = Duration.between(start, finish).toSeconds();
        System.out.printf("Execution took: %.2f min (%d seconds)\n", (float)timeElapsed/60, timeElapsed);

    }
}