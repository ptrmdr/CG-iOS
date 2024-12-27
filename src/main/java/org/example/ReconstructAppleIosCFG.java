package org.example;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.util.SymbolicPropogator;
import org.apache.tinkerpop.gremlin.process.traversal.IO;
import org.apache.tinkerpop.gremlin.process.traversal.Merge;
import org.apache.tinkerpop.gremlin.process.traversal.dsl.graph.GraphTraversalSource;
import org.apache.tinkerpop.gremlin.structure.T;
import org.apache.tinkerpop.gremlin.structure.Vertex;
import org.apache.tinkerpop.gremlin.tinkergraph.structure.TinkerGraph;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.regex.Pattern;

import static org.apache.tinkerpop.gremlin.process.traversal.AnonymousTraversalSource.traversal;
import static org.apache.tinkerpop.gremlin.process.traversal.dsl.graph.__.out;

public class ReconstructAppleIosCFG extends GhidraScript {
    public static final String ENTRY_POINT_PATTERN_LIST_FILE_NAME = "entry_points.txt";
    public static final String SOURCE_PATTERN_LIST_FILE_NAME = "info_sources.txt";
    public static final String SINK_PATTERN_LIST_FILE_NAME = "info_sinks.txt";

    private Set<Pattern> entryPointFuncNames = new HashSet<>();
    private Set<Pattern> infoSourceFuncNames = new HashSet<>();
    private Set<Pattern> infoSinkFuncNames = new HashSet<>();

    @Override
    protected void run() throws Exception {
        TinkerGraph graph = TinkerGraph.open();
        GraphTraversalSource g;

        String filename = currentProgram.getDomainFile().getName();
        graph.createIndex("address", Vertex.class);
        g = traversal().withEmbedded(graph);
        try {
            g.io(String.format("./tmp_%s.json", filename)).read().iterate();
        } catch (IllegalStateException e) {
            printerr("file not found");
            return;
        }
        initFunctionPatternLists();

        FunctionIterator fIter = currentProgram.getFunctionManager().getFunctions(true);
        Set<Function> funcWorklist = new LinkedHashSet<>();

        IndirectCallEvaluator evalType = new IndirectCallEvaluator(monitor, true, g, false);
        fIter.forEach(funcWorklist::add);

        while (!funcWorklist.isEmpty()) {
            if (monitor.isCancelled()) break;

            Iterator<Function> iterator = funcWorklist.iterator();
            Function f = iterator.next();
            iterator.remove();

            boolean is_ep = entryPointFuncNames.stream().anyMatch(p -> p.matcher(f.getName()).matches());
            boolean is_source = infoSourceFuncNames.stream().anyMatch(p -> p.matcher(f.getName()).matches());
            boolean is_sink = infoSinkFuncNames.stream().anyMatch(p -> p.matcher(f.getName()).matches());

            g.mergeV(Map.of(
                    T.label, "FUNCTION",
                    "name", f.getName(),
                    "address", f.getEntryPoint().getOffset()

            ))
                    .option(Merge.onCreate, Map.of(
                                    "is_ext", f.isExternal(),
                                    "is_thunk", f.isThunk(),
                                    "is_ep", is_ep,
                                    "is_source", is_source,
                                    "is_sink", is_sink))
                    .option(Merge.onMatch, Map.of(
                                    "is_ext", f.isExternal(),
                                    "is_thunk", f.isThunk(),
                                    "is_ep", is_ep,
                                    "is_source", is_source,
                                    "is_sink", is_sink))
                    .next();

            if (f.isExternal()
                    || f.isThunk()) continue;
            println("======= " + f.getName() + " (at " + f.getEntryPoint() + ")" + " =======");

            Address entry = f.getEntryPoint();
            SymbolicPropogator symProp = new SymbolicPropogator(currentProgram);

            symProp.setDebug(false);
            symProp.flowConstants(entry, f.getBody(), evalType, true, monitor);

            boolean addedToWorklist = funcWorklist.addAll(evalType.getChangedFunctions());
            evalType.clearChangedFunctions();
        }

        println("writing graph to file");
        g.io(String.format("%s.json", filename)).with(IO.writer, IO.graphson).write().iterate();
        g.io(String.format("%s.graphml", filename)).with(IO.writer, IO.graphml).write().iterate();

        TinkerGraph subGraph = (TinkerGraph) g.E()
                .hasLabel("CALLS")
                .subgraph("subGraph").cap("subGraph").next();
        GraphTraversalSource sg = traversal().withEmbedded(subGraph);
        Set<Vertex> funcs = sg.V().has("is_ep", true).repeat(out("CALLS")).emit().toSet();
        println("Num of vert: " + funcs.size());
        sg.io(String.format("%s_cg.graphml", filename)).with(IO.writer, IO.graphml).write().iterate();
        g.close();

    }

    private void initFunctionPatternLists() {
        try {
            List<String> allPatterns = Files.readAllLines(Paths.get(ENTRY_POINT_PATTERN_LIST_FILE_NAME));

            for (String patternStr : allPatterns) {
                entryPointFuncNames.add(Pattern.compile(patternStr));
            }
        } catch (IOException e) {
            println("exception while reading from " + ENTRY_POINT_PATTERN_LIST_FILE_NAME);
        }

        try {
            List<String> allPatterns = Files.readAllLines(Paths.get(SOURCE_PATTERN_LIST_FILE_NAME));

            for (String patternStr : allPatterns) {
                infoSourceFuncNames.add(Pattern.compile(patternStr));
            }
        } catch (IOException e) {
            println("exception while reading from " + SOURCE_PATTERN_LIST_FILE_NAME);
        }

        try {
            List<String> allPatterns = Files.readAllLines(Paths.get(SINK_PATTERN_LIST_FILE_NAME));

            for (String patternStr : allPatterns) {
                infoSinkFuncNames.add(Pattern.compile(patternStr));
            }
        } catch (IOException e) {
            println("exception while reading from " + SINK_PATTERN_LIST_FILE_NAME);
        }

    }
}
