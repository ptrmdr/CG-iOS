package org.example;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.format.objc2.ObjectiveC2_Constants;
import ghidra.app.util.bin.format.swift.SwiftUtils;
import ghidra.app.util.demangler.DemangledException;
import ghidra.app.util.demangler.swift.*;
import ghidra.app.util.demangler.swift.nodes.SwiftNode;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.LabelHistory;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import org.apache.tinkerpop.gremlin.process.traversal.IO;
import org.apache.tinkerpop.gremlin.process.traversal.Merge;
import org.apache.tinkerpop.gremlin.process.traversal.dsl.graph.GraphTraversalSource;
import org.apache.tinkerpop.gremlin.structure.*;
import org.apache.tinkerpop.gremlin.tinkergraph.structure.TinkerGraph;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.apache.tinkerpop.gremlin.process.traversal.AnonymousTraversalSource.traversal;
import static org.apache.tinkerpop.gremlin.process.traversal.dsl.graph.__.outE;

public class ExtractMachOTypeHierarchy extends GhidraScript {
    Graph graph = TinkerGraph.open();
    GraphTraversalSource g = traversal().withEmbedded(graph);

    DataType classDescriptorType;
    DataType protocolDescriptorType;
    DataType structDescriptorType;
    DataType enumDescriptorType;
    DataType protocolConformanceDescriptorType;

    DataType objc_class_t;

    ArrayList<Data> classes = new ArrayList<>();
    ArrayList<Data> protocols = new ArrayList<>();


    SwiftDemanglerOptions options = new SwiftDemanglerOptions();

    SwiftDemangler demangler;
    SwiftNativeDemangler nativeDemangler;

    @Override
    protected void run() throws Exception {
        if (!(SwiftUtils.isSwift(currentProgram) || ObjectiveC2_Constants.isObjectiveC2(currentProgram))) {
            printerr("This script only works for swift binaries");
            return;
        }

        demangler = new SwiftDemangler(currentProgram);
        nativeDemangler = new SwiftNativeDemangler(options.getSwiftDir());

        boolean loadGraph = false;
        if (loadGraph) {
            try {
                g.io("./test.json").read().iterate();
            } catch (IllegalStateException e) {
                printerr("file not found");
            }
        }

        initializeDataTypes();

        DataIterator data = currentProgram.getListing().getData(true);

        while (data.hasNext()) {
            getMonitor().checkCancelled();

            Data d = data.next();
            if (d != null) {
                handleData(d);
            }
        }

        List<Edge> l = g
                .V().as("a")
                .outE("HAS_PROTOCOL").as("b").toList();
        l.forEach(edge -> println(String.format("%s implements protocol %s", edge.outVertex().property("name"), edge.inVertex().property("name"))));

        l = g
                .V().as("a")
                .outE("HAS_SUPERCLASS").as("b").toList();
        l.forEach(edge -> println(String.format("%s extends %s", edge.outVertex().property("name"), edge.inVertex().property("name"))));

        //Add some special top element
        Vertex topElemV = g.mergeV(Map.of(
                T.label, "CLASS",
                "name", "TOP_ELEMENT_TYPES",
                "address", -1L
        )).next();

        Set<Vertex> topVs = g.V().hasLabel("CLASS", "STRUCT", "PROTOCOL")
                .where(outE("HAS_SUPERCLASS", "HAS_PROTOCOL", "IS_A").count().is(0))
                .toSet();

        for (Vertex v : topVs) {
            g.mergeE(Map.of(
                    T.label, "IS_A",
                    Direction.from, v, Direction.to, topElemV
            )).iterate();
        }

        String filename = currentProgram.getDomainFile().getName();
        g.io(String.format("tmp_%s.json", filename)).with(IO.writer, IO.graphson).write().iterate();
        g.io(String.format("tmp_%s.graphml", filename)).with(IO.writer, IO.graphml).write().iterate();
        g.close();
    }

    private void initializeDataTypes() {
        DataTypeManager dtm = currentProgram.getDataTypeManager();

        classDescriptorType = dtm.getDataType("/SwiftTypeMetadata/TargetClassDescriptor");
        protocolDescriptorType = dtm.getDataType("/SwiftTypeMetadata/TargetProtocolDescriptor");
        structDescriptorType = dtm.getDataType("/SwiftTypeMetadata/TargetStructDescriptor");
        enumDescriptorType = dtm.getDataType("/SwiftTypeMetadata/TargetEnumDescriptor");
        protocolConformanceDescriptorType = dtm.getDataType("/SwiftTypeMetadata/TargetProtocolConformanceDescriptor");

        objc_class_t = dtm.getDataType("/_objc2_/class_t");
    }

    private void handleData(Data d) {
        if (d.isStructure()) {

            //if (handleContextType(d) != null) return;


            SwiftDemangledTree demangledTree = getSwiftDemangledTreeFor(d.getAddress());
            if (demangledTree == null) return;

            if (isDemangledTreeOfKind(demangledTree, SwiftDemangledNodeKind.ProtocolDescriptor)) {
                protocols.add(d);
                handleProtocol(d);
            } else if (isDemangledTreeOfKind(demangledTree, SwiftDemangledNodeKind.ProtocolConformanceDescriptor)) {
                handleProtocolConformance(d);
            } else if (isDemangledTreeOfKind(demangledTree, SwiftDemangledNodeKind.NominalTypeDescriptor)) {
                handleNominalType(d);
            } else if (d.getDataType().equals(objc_class_t)) {
                handleObjcClassT(d);
            }
            /*
            if (d.getDataType().equals(protocolConformanceDescriptorType)) {
                handleProtocolConformance(d);
            */
        }
    }

    private Vertex handleNominalType(Data d) {
        String label;
        Address addr = d.getAddress();
        String name = d.getLabel();
        if (d.getDataType().equals(classDescriptorType)) {
            classes.add(d);

            println("class: ");
            SwiftDemangledTree demangledTree = getSwiftDemangledTreeFor(d.getAddress());
            label = "CLASS";
            //v = handleClass(d);
        } else if (d.getDataType().equals(structDescriptorType)) {

            println("struct: ");
            SwiftDemangledTree demangledTree = getSwiftDemangledTreeFor(d.getAddress());
            label = "STRUCT";
            //v = handleStruct(d);
        } else if (d.getDataType().equals(enumDescriptorType)) {

            println("enum: ");
            label = "ENUM";
            SwiftDemangledTree demangledTree = getSwiftDemangledTreeFor(d.getAddress());
            //v = handleEnum(d);
        } else {
            return null;
        }

        Vertex v = g.mergeV(Map.of(
                T.label, label,
                "name", name,
                "address", addr.getOffset()
        )).next();

        return v;
    }



    private Vertex handleContextType(Data d) {
        Vertex v;
        if (d == null) return null;
        if (d.getDataType().equals(classDescriptorType)) {
            classes.add(d);

            println("class: ");
            SwiftDemangledTree demangledTree = getSwiftDemangledTreeFor(d.getAddress());
            boolean t = demangledTree.getRoot().walkAndTest(s -> s.getKind() == SwiftDemangledNodeKind.Class);
            String n = t? extractNodeOfKind(demangledTree, SwiftDemangledNodeKind.Class).getChild(
                    SwiftDemangledNodeKind.Identifier).getText() : " ";
            println("  " + t + " " + n + " ");
            v = handleClass(d);
        } else if (d.getDataType().equals(protocolDescriptorType)) {
            protocols.add(d);
            v = handleProtocol(d);
        } else if (d.getDataType().equals(structDescriptorType)) {

            println("struct: ");
            SwiftDemangledTree demangledTree = getSwiftDemangledTreeFor(d.getAddress());
            v = handleStruct(d);
        } else if (d.getDataType().equals(enumDescriptorType)) {

            println("enum: ");
            SwiftDemangledTree demangledTree = getSwiftDemangledTreeFor(d.getAddress());
            v = handleEnum(d);
        } else {

            println("else: ");
            SwiftDemangledTree demangledTree = getSwiftDemangledTreeFor(d.getAddress());
            v = null;
            g.mergeV(Map.of(
                    T.label, "CLASS",
                    "name", "unknown_type",
                    "address", -1L)
            ).next();
        }

        return v;
    }

    private Vertex handleProtocol(Data protocol) {
        Vertex v = null;
        SymbolTable symbolTable = currentProgram.getSymbolTable();

        if (protocol.isStructure()) {
            v = g.mergeV(Map.of(
                    T.label, "PROTOCOL",
                    "name", protocol.getLabel(),
                    "address", protocol.getAddress().getOffset()
            )).next();
        } else if (protocol.isPointer()) {
            Address protocolAddress = protocol.getAddress(0);
            LabelHistory protocolLabelHist = Arrays.stream(symbolTable.getLabelHistory(protocolAddress)).toList().getLast();
            String protocolLabel = protocolLabelHist.getLabelString();

            v = g.mergeV(Map.of(
                    T.label, "PROTOCOL",
                    "name", protocolLabel,
                    "address", protocolAddress.getOffset()
            )).next();
        }

        return v;
    }

    private Vertex handleClass(Data classStruct) {
        Vertex classV = g.mergeV(Map.of(
                T.label, "CLASS",
                "name", classStruct.getLabel(),
                "address", classStruct.getAddress().getOffset()
        )).next();

        Address mangledSuperClassRef = classStruct.getComponent(1).getAddress(0);
        if (mangledSuperClassRef != null) {
            try {
                byte refKind = getByte(mangledSuperClassRef);
                int superClassOffset = getInt(mangledSuperClassRef.add(1));
                if (refKind == 1) {
                    // refKind \x01 is a direct pointer to the descriptor
                    Data superClassStruct = getDataAt(mangledSuperClassRef.add(superClassOffset + 1));

                    Vertex superClassV = g.mergeV(Map.of(
                            T.label, "CLASS",
                            "name", superClassStruct.getLabel(),
                            "address", superClassStruct.getAddress().getOffset()
                    )).next();

                    g.mergeE(Map.of(
                            T.label, "HAS_SUPERCLASS",
                            Direction.from, classV, Direction.to, superClassV
                    )).iterate();

                } else {
                    Data pointerToDescriptor = getDataAt(mangledSuperClassRef.add(superClassOffset + 1));
                    printerr("TODO: not done yet");
                }
            } catch (MemoryAccessException memoryAccessException) {
                printerr(String.format(
                        "Failed accessing superclass info of %s at %s", classStruct.getLabel(), mangledSuperClassRef
                ));
            }
        } else {
            // TODO: anyobject/anyclass edge
        }

        return classV;
    }

    private Vertex handleStruct(Data struct) {
        Vertex v = g.mergeV(Map.of(
                T.label, "STRUCT",
                "name", struct.getLabel(),
                "address", struct.getAddress().getOffset()
        )).next();

        return v;
    }

    private Vertex handleEnum(Data enumData) {
        Vertex v = g.mergeV(Map.of(
                T.label, "ENUM",
                "name", enumData.getLabel(),
                "address", enumData.getAddress().getOffset()
        )).next();

        return v;
    }

    private boolean isProtocolWitness(SwiftDemangledTree tree) {
        return isDemangledTreeOfKind(tree, SwiftDemangledNodeKind.ProtocolWitness);
    }

    private SwiftNode extractNodeOfKind(SwiftDemangledTree tree, SwiftDemangledNodeKind nodeKind) {
        SwiftNode r = tree.getRoot();
        return extractNodeOfKind(r, nodeKind);
    }

    private SwiftNode extractNodeOfKind(SwiftNode root, SwiftDemangledNodeKind nodeKind) {
        if (root == null || root.getKind() == nodeKind) {
            return root;
        }

        for (SwiftNode c : root.getChildren()) {
            if (c.getKind() == nodeKind) return c;

            return extractNodeOfKind(c, nodeKind);
        }
        return null;
    }

    private boolean isDemangledTreeOfKind(SwiftDemangledTree tree, SwiftDemangledNodeKind nodeKind) {
        SwiftNode root = tree.getRoot();

        return root.getKind() == nodeKind
                || (root.getKind() == SwiftDemangledNodeKind.Global && root.hasChild(nodeKind));
    }

    private SwiftDemangledTree getSwiftDemangledTreeFor(Address a) {
        String mangled = null;
        SymbolTable symbolTable = currentProgram.getSymbolTable();

        for (Symbol symbol : symbolTable.getSymbols(a)) {
            if (demangler.isSwiftMangledSymbol(symbol.getName())) {
                mangled = symbol.getName();
                break;
            }
            for (LabelHistory history : symbolTable.getLabelHistory(currentAddress)) {
                if (demangler.isSwiftMangledSymbol(history.getLabelString())) {
                    mangled = history.getLabelString();
                    break;
                }
            }
        }
        if (mangled == null) {
            println("No mangled Swift symbols found at " + currentAddress);
            return null;
        }

        SwiftDemangledTree demangledTree;
        try {
            demangledTree = new SwiftDemangledTree(nativeDemangler, mangled);
        } catch (DemangledException e) {
            println("failed to demangle " + mangled);
            return null;
        }
        SwiftNode root = demangledTree.getRoot();

        println("found root: " + root + " and children: " + root.getChildren());
        println("  for " + mangled);

        return demangledTree;
    }

    private Edge handleProtocolConformance(Data conformance) {
        long protocolOffset = conformance.getComponent(0).getScalar(0).getValue();
        Data protocolData = getDataContaining(conformance.getComponent(0).getAddress().add(protocolOffset));

        Data conformingTypeData = getDataAt(conformance.getComponent(1).getAddress(0));

        Vertex protocolV = handleProtocol(protocolData);
        Vertex conformingTypeV = handleContextType(conformingTypeData);
        if (conformingTypeV == null) return null;
        Edge e = g.mergeE(Map.of(
                T.label, "HAS_PROTOCOL",
                Direction.from, conformingTypeV, Direction.to, protocolV
        )).next();

        long pwtOffset = conformance.getComponent(2).getScalar(0).getValue();
        if (pwtOffset != 0) {
            Address address = conformance.getComponent(2).getAddress().add(pwtOffset);

            Vertex pwtV = g.mergeV(Map.of(
                    T.label, "WITNESSTABLE",
                    "address", address.getOffset()
            )).next();
            g.mergeE(Map.of(
                    T.label, "HAS_PWT",
                    Direction.from, conformingTypeV, Direction.to, pwtV
            )).iterate();
            g.mergeE(Map.of(
                    T.label, "HAS_PWT",
                    Direction.from, protocolV, Direction.to, pwtV
            )).iterate();

            Data pwt = getDataAt(address);

            Data w = getDataAfter(pwt);
            //TODO: use demangling instead of regex on demangle tool string output
            Pattern pattern = Pattern.compile(
                    "\\$\\$protocol_witness_for_(?<method>.+)_.+_(?<ret>.+)_in_conformance_(?<conform>.+)_:_(?<proto>.+)_in_"
            );
            while (w != null && getFunctionAt(w.getAddress(0)) != null) {
                Function f = getFunctionAt(w.getAddress(0));

                SwiftDemangledTree demangledTree = getSwiftDemangledTreeFor(w.getAddress(0));
                if (demangledTree != null && isProtocolWitness(demangledTree)) {
                    Matcher m = pattern.matcher(f.getName());
                    String methodName = m.find() ? m.group("method") : f.getName();
                    long index = w.getAddress().subtract(pwt.getAddress());
                    Vertex methodV = g.mergeV(Map.of(
                            T.label, "METHOD",
                            "name", methodName,
                            "tableindex", index
                    )).next();

                    Vertex funcV = g.mergeV(Map.of(
                            T.label, "FUNCTION",
                            "name", f.getName(),
                            "address", f.getEntryPoint().getOffset()
                    )).option(Merge.onCreate, Map.of(
                            "is_ext", f.isExternal(),
                            "is_thunk", f.isThunk(),
                            "is_ep", false
                    )).next();
                    g.mergeE(Map.of(
                            T.label, "HAS_METHOD",
                            Direction.from, protocolV, Direction.to, methodV
                    )).iterate();
                    g.mergeE(Map.of(
                            T.label, "HAS_WITNESS",
                            "tableindex", index,
                            Direction.from, pwtV, Direction.to, funcV
                    )).iterate();
                }
                w = getDataAfter(w);
            }
        }
        return e;
    }

    private Vertex handleObjcClassT(Data objcClass) {
        Address isaAddr = objcClass.getComponent(0).getAddress(0);
        Data isa = getDataAt(isaAddr);

        Address superClassAddr = objcClass.getComponent(1).getAddress(0);
        Data superClassObjc = getDataAt(superClassAddr);

        Address swiftDescriptorAddr = getDataAfter(objcClass).getAddress(0);
        Data swiftDescriptor = swiftDescriptorAddr != null ? getDataAt(swiftDescriptorAddr) : null;

        boolean isClass = swiftDescriptor != null && swiftDescriptor.isStructure();
        String classLabel = isClass ? swiftDescriptor.getLabel() : objcClass.getLabel();
        Address classAddr = isClass ? swiftDescriptor.getAddress() : objcClass.getAddress();

        LabelHistory[] isaLHist = currentProgram.getSymbolTable().getLabelHistory(isaAddr);
        String isaLabel = isa != null ? isa.getLabel() : isaLHist[0].getLabelString();
        // TODO: look into class address
        Vertex classV = g.mergeV(Map.of(
                T.label, "CLASS",
                "name", classLabel,
                "address", classAddr.getOffset()
        )).option(Merge.onMatch, Map.of("address_objc_class", objcClass.getAddress().getOffset())).next();

        Vertex isaV = g.mergeV(Map.of(
                T.label, "CLASS",
                "name", isaLabel,
                "address", isaAddr.getOffset()
        )).next();

        Vertex superClassV = null;
        if (isClass && superClassObjc != null) {
            superClassV = handleObjcClassT(superClassObjc);
        } else {
            LabelHistory[] superClassLHist = currentProgram.getSymbolTable().getLabelHistory(superClassAddr);
            String superClassLabel = superClassObjc != null ?
                    superClassObjc.getLabel() : superClassLHist[0].getLabelString();
            superClassV = g.mergeV(Map.of(
                    T.label, "CLASS",
                    "name", superClassLabel,
                    "address", superClassAddr.getOffset()
            )).next();
        }
        if (isClass) {
            g.mergeE(Map.of(
                    T.label, "HAS_SUPERCLASS",
                    Direction.from, classV, Direction.to, superClassV
            )).iterate();
            g.mergeE(Map.of(
                    T.label, "IS_A",
                    Direction.from, classV, Direction.to, isaV
            )).iterate();
            processObjCMethods(objcClass, getDataAfter(getDataAfter(objcClass)), classV);
        } else {
            g.mergeE(Map.of(
                    T.label, "IS_A",
                    Direction.from, classV, Direction.to, superClassV
            )).iterate();
        }
        return classV;
    }

    private void processObjCMethods(Data objcClass, Data methodData, Vertex classV) {
        while (methodData != null && methodData.isPointer() && getFunctionAt(methodData.getAddress(0)) != null) {
            Function f = getFunctionAt(methodData.getAddress(0));
            Vertex methodV = g.mergeV(Map.of(
                    T.label, "METHOD",
                    "name", f.getName(),
                    "address", methodData.getAddress().getOffset(),
                    "tableindex", methodData.getAddress().subtract(objcClass.getAddress())
            )).next();

            Vertex funcV = g.mergeV(Map.of(
                    T.label, "FUNCTION",
                    "name", f.getName(),
                    "address", f.getEntryPoint().getOffset()
            )).option(Merge.onCreate, Map.of(
                    "is_ext", f.isExternal(),
                    "is_thunk", f.isThunk(),
                    "is_ep", false
            )).next();

            g.mergeE(Map.of(
                    T.label, "HAS_METHOD",
                    Direction.from, classV,
                    Direction.to, methodV
            )).iterate();
            g.mergeE(Map.of(
                    T.label, "IMPLEMENTS",
                    Direction.from, funcV,
                    Direction.to, methodV
            )).iterate();

            methodData = getDataAfter(methodData);
        }
    }

}
