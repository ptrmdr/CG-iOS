package org.example;

import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
import ghidra.app.script.ScriptMessage;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ContextEvaluator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.Msg;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;
import org.apache.tinkerpop.gremlin.process.traversal.Merge;
import org.apache.tinkerpop.gremlin.process.traversal.dsl.graph.GraphTraversal;
import org.apache.tinkerpop.gremlin.process.traversal.dsl.graph.GraphTraversalSource;
import org.apache.tinkerpop.gremlin.structure.Direction;
import org.apache.tinkerpop.gremlin.structure.T;
import org.apache.tinkerpop.gremlin.structure.Vertex;

import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;

import static org.apache.tinkerpop.gremlin.process.traversal.dsl.graph.__.*;
import static org.apache.tinkerpop.gremlin.process.traversal.dsl.graph.__.is;

public class IndirectCallEvaluator extends ConstantPropagationContextEvaluator {
    private boolean debug = false;
    private GraphTraversalSource g;
    private Map<Function, Map<Register, Address>> functionSignatures = new HashMap<>();
    private Map<Function, Address> functionReturnType = new HashMap<>();
    private Map<Address, Map<Register, Address>> callSignatures = new HashMap<>();
    private Set<Function> changedFunctions = new HashSet<>();


    public IndirectCallEvaluator(TaskMonitor monitor, boolean trustMemoryWrite, GraphTraversalSource g, boolean debug) {
        super(monitor, trustMemoryWrite);
        this.debug = debug;
        this.g = g;
    }

    public Set<Function> getChangedFunctions() {
        return changedFunctions;
    }

    public void clearChangedFunctions() {
        changedFunctions = new HashSet<>();
    }

    protected void println(String message) {
        if (!this.debug) return;
        String scriptName = "IndirectCallEval";
        String decoratedMessage = scriptName + ">>> " + message;
        Msg.info(ContextEvaluator.class, new ScriptMessage(decoratedMessage));
    }

    private Address resolveTypeCache(VarnodeContext context, Address address) throws NotFoundException {
        if (address.isStackAddress()) throw new NotFoundException();
        Varnode addrVar = context.getVarnode(address.getAddressSpace().getSpaceID(), address.getOffset(), 4);
        Varnode cacheData = context.getValue(addrVar, this);
        Address descriptorAddr = Address.NO_ADDRESS;
        try {
            Address symbolic = address.add(cacheData.getOffset());


            addrVar = context.getVarnode(symbolic.getAddressSpace().getSpaceID(), symbolic.getOffset(), 1);
            int ptrType = (int) context.getValue(addrVar, this).getOffset();


            Address ptr = symbolic.add(1);
            addrVar = context.getVarnode(ptr.getAddressSpace().getSpaceID(), ptr.getOffset(), 4);
            if (ptrType == 1) {
                int relOffset = (int) context.getValue(addrVar, this).getOffset();
                descriptorAddr = ptr.add(relOffset);
            } else if (ptrType == 2) {
                int relOffset = (int) context.getValue(addrVar, this).getOffset();
                ptr = ptr.add(relOffset);

                addrVar = context.getVarnode(ptr.getAddressSpace().getSpaceID(), ptr.getOffset(), 8);
                long offset = context.getValue(addrVar, this).getOffset();
                descriptorAddr = ptr.getNewAddress(offset);
            }
        } catch (AddressOutOfBoundsException e) {
            println("not a valid address");
            return Address.NO_ADDRESS;
        }
        return descriptorAddr;
    }

    private boolean graphContainsFunction(Address address) {
        if (address == null || address == Address.NO_ADDRESS) return false;

        boolean result = g.V()
                .hasLabel("FUNCTION")
                .has("address", address.getOffset())
                .hasNext();
        println("checking graph for func at " + address + " " + result);
        return result;
    }

    private boolean graphContainsType(Address address) {
        if (address == null || address == Address.NO_ADDRESS) return false;

        boolean result = g.V()
                .hasLabel("PROTOCOL", "STRUCT", "CLASS")
                .has("address", address.getOffset())
                .hasNext();
        println("checking graph for type at " + address + " " + result);
        return result;
    }

    private Vertex lowestCommonAncestor(Vertex a, Vertex b) {
        println("lub of " + a.value("name") + " U " + b.value("name"));

        if (a.value("address") == b.value("address")) return a;
        GraphTraversal<Vertex, Vertex> c = g.V(a)
                .emit(hasLabel("PROTOCOL", "STRUCT", "CLASS")).as("x")
                .repeat(out())
                .repeat(in())
                .emit(or(is(a), is(b)))
                .select("x");

        Vertex result = c.hasNext() ?
                c.next()
                : g.V().has("CLASS", "name", "TOP_ELEMENT_TYPES").next();


        println("  is " + result.value("name"));

        return result;
    }

    private Address commonSuperType(Program p, Collection<Address> typeRefs) {
        Vertex resultV = null;
        for (Address typeAddr : typeRefs) {
            List<Vertex> vertices = g.V().has("address", typeAddr.getOffset()).toList();
            if (vertices.isEmpty()) continue;

            resultV = resultV != null ? lowestCommonAncestor(resultV, vertices.getFirst()) : vertices.getFirst();
        }

        if (resultV == null) return null;

        int space = p.getAddressFactory().getDefaultAddressSpace().getSpaceID();
        return p.getAddressFactory().getAddress(space, resultV.value("address"));
    }

    private void evaluateParameterBefore(VarnodeContext context, Instruction instr) {
        PrototypeModel cconv = instr.getProgram().getFunctionManager().getDefaultCallingConvention();
        Set<Register> inputRegisters = Arrays.stream(cconv.getPotentialInputRegisterStorage(instr.getProgram()))
                .map(VariableStorage::getRegister)
                .collect(Collectors.toSet());
        Set<Address> typeRefs = new HashSet<>();
        Map<Register, Address> inputTypes = new HashMap<>();
        AddressSpace memspace = instr.getProgram().getAddressFactory().getDefaultAddressSpace();
        Program p = instr.getProgram();

        for (Register r : inputRegisters) {
            RegisterValue rval = context.getRegisterValue(r);
            if (rval != null) {
                Address typeRef;
                try {
                    Varnode rvar = context.getVarnode(memspace.getSpaceID(), rval.getUnsignedValue().longValue(), 8);
                    println("Rvar "+ r + " = " + rvar);
                    typeRef = graphContainsType(rvar.getAddress()) ?
                            rvar.getAddress()
                            : resolveTypeCache(context, rvar.getAddress());
                } catch (NotFoundException ignored) {
                    continue;
                }
                if (graphContainsType(typeRef)) {
                    typeRefs.add(typeRef);
                    inputTypes.put(r, typeRef);
                }
            }
        }

        Register x20 = context.getRegister("x20");
        RegisterValue rval = context.getRegisterValue(x20);
        if (rval != null) {
            Varnode rvar = context.getVarnode(memspace.getSpaceID(), rval.getUnsignedValue().longValue(), 8);
            println("Rvar " + x20 + " = " + rvar);
            boolean hasThisType = graphContainsType(rvar.getAddress());
            if (hasThisType) {
                inputTypes.put(x20, rvar.getAddress());
            }

        }
        // save indirect return location
        Register x8 = context.getRegister("x8");
        Varnode retAddr = context.getRegisterVarnodeValue(x8);
        if (context.isStackSymbolicSpace(retAddr)) {
            inputTypes.put(x8, retAddr.getAddress());
            Reference ref = p.getReferenceManager().addStackReference(
                    instr.getMinAddress(), instr.getPcode().length-1,
                    (int) retAddr.getOffset(),
                    RefType.PARAM, SourceType.USER_DEFINED);

            println("creating ref to indirect return location at: " + retAddr);
            println("  " + ref);
        }

        Address superType = commonSuperType(instr.getProgram(), typeRefs);
        if (superType != null) {
            // some reference to store the possible return type of the call
            println("creating ref to super type at: " + superType);
            p.getReferenceManager().addMemoryReference(
                    instr.getMinAddress(), superType, RefType.PARAM, SourceType.USER_DEFINED, 0);
        }
        callSignatures.put(instr.getAddress(), inputTypes);
    }

    private Set<Varnode> getPWTAddresses(VarnodeContext context, Varnode typeAddr) {
        Set<Object> pwts = g.V()
                .has("address", typeAddr.getOffset())
                .out("HAS_PWT")
                .values("address").toSet();
        return pwts.stream()
                .map(a -> context.createConstantVarnode((Long) a, 8))
                .collect(Collectors.toSet());
    }

    private void createExistentialContainer(VarnodeContext context, Instruction instr, Varnode outAddr, Varnode typeAddr) {
        // write type into existential container
        Set<Varnode> pwts = getPWTAddresses(context, typeAddr);
        for (int i = 0; i < 4; i++) {
            Address a = outAddr.getAddress().add(i * 8);
            Varnode varA = context.getVarnode(outAddr.getSpace(), a.getOffset(), outAddr.getSize());
            context.putValue(varA, typeAddr, false);
        }
        // write one pwt into last row of container
        if (!pwts.isEmpty()) {
            Address a = outAddr.getAddress().add(4 * 8);
            Varnode varA = context.getVarnode(outAddr.getSpace(), a.getOffset(), outAddr.getSize());
            context.putValue(varA, pwts.iterator().next(), false);
        }

    }

    private boolean isProtocolWitness(Address target) {
        return g.V()
                .has("FUNCTION", "address", target.getOffset())
                .in("HAS_WITNESS")
                .hasNext();
    }

    private Set<Vertex> findRelatedWitnesses(Address target) {
        long offset = (long) g.V()
                .has("FUNCTION", "address", target.getOffset())
                .inE("HAS_WITNESS")
                .values("tableindex").next();
        return g.V()
                .has("FUNCTION", "address", target.getOffset())
                .in("HAS_WITNESS").in("HAS_PWT").hasLabel("PROTOCOL")
                .out("HAS_PWT").outE("HAS_WITNESS").has("tableindex", offset).inV()
                .hasLabel("FUNCTION").toSet();
    }

    private void mergeIntoFunctionSignature(Function f, Map<Register, Address> a) {
        Map<Register, Address> result = this.functionSignatures.getOrDefault(f, new HashMap<>());
        boolean changed = false;
        for (Register r : a.keySet()) {
            Address lub = result.containsKey(r) && result.get(r) != null ?
                    commonSuperType(f.getProgram(), List.of(result.get(r), a.get(r)))
                    : a.get(r);
            if (lub == null) continue;
            Address prev = result.put(r, lub);
            if (prev == null || prev.getOffset() != lub.getOffset()) {
                println("merge changed " + prev + " to " + lub);
                changed = true;
            }

        }
        this.functionSignatures.put(f, result);
        if (changed) changedFunctions.add(f);
    }

    private void handleCalls(VarnodeContext context, Instruction instr, RefType refType, Address target) {
        Function caller = instr.getProgram().getFunctionManager().getFunctionContaining(instr.getAddress());
        Function callee = instr.getProgram().getFunctionManager().getFunctionAt(target);
        if (caller == null || callee == null) {
            //println("Could not find caller / callee " + caller + " / " + callee );
            return;
        }
        // find or create caller and callee vertices
        Function f = caller;
        Vertex callerV = g.mergeV(Map.of(
                T.label, "FUNCTION",
                "name", f.getName(),
                "address", f.getEntryPoint().getOffset()

        )).next();
        f = callee;
        Vertex calleeV = g.mergeV(Map.of(
                T.label, "FUNCTION",
                "name", f.getName(),
                "address", f.getEntryPoint().getOffset()

        ))
                .option(Merge.onCreate, Map.of(
                        "is_ext", f.isExternal(),
                        "is_thunk", f.isThunk()))
                .next();

        Map<Register, Address> callSignature = callSignatures.getOrDefault(instr.getAddress(), new HashMap<>());

        if (refType.isComputed() && isProtocolWitness(target)) {
            println("Found some witness call dest at 0x" + instr.getAddress() + " to " + target);
            Set<Vertex> witnesses = findRelatedWitnesses(target);
            for (Vertex witnessV : witnesses) {
                Address entry = f.getEntryPoint().getNewAddress(witnessV.value("address"));
                Function w = instr.getProgram().getFunctionManager().getFunctionAt(entry);
                if (w != null) {
                    Register x20 = context.getRegister("x20");
                    if (callSignature.get(x20) != null) {
                        DataType dataTypeClassT = w.getProgram().getDataTypeManager().getDataType("/_objc2_/class_t");
                        Vertex classTypeV = getConformingTypeOfWitness(witnessV);

                        Address classType = w.getEntryPoint().getNewAddress(classTypeV.value("address"));
                        ReferenceIterator refIter = w.getProgram().getReferenceManager().getReferencesTo(classType);
                        while (refIter.hasNext()) {
                            Reference ref = refIter.next();

                            Data d = w.getProgram().getListing().getDataAt(ref.getFromAddress());

                            if (d != null && d.getDataType().equals(dataTypeClassT)) {
                                Address old = callSignature.put(x20, d.getAddress());
                                println("put conforming type " + d.getAddress() + " for " + w.getName() + " (old: " + old + ")");
                                break;
                            }
                        }
                    }
                    println("computed merge at " + instr.getAddress() + ", " + refType);
                    mergeIntoFunctionSignature(w, callSignature);
                    // overwrite assumed with computed return type
                    if (functionReturnType.containsKey(w)) {
                        Address computedRetType = functionReturnType.get(w);
                        instr.getProgram().getReferenceManager().removeAllReferencesFrom(instr.getMaxAddress());
                        instr.getProgram().getReferenceManager().addMemoryReference(
                                instr.getMaxAddress(), computedRetType,
                                RefType.PARAM, SourceType.USER_DEFINED, 0);
                    }

                }
                /*g.mergeE(Map.of(
                        T.label, "CALLS",
                        Direction.from, callerV, Direction.to, witnessV
                ))
                        .option(Merge.onCreate, Map.of("is_computed", refType.isComputed()))
                        .option(Merge.onMatch, Map.of("is_computed", refType.isComputed()))
                        .iterate();*/
            }
        } else if (!isProtocolWitness(target)) {
            println("Found some call dest at 0x" + instr.getAddress() + " to " + target);
            mergeIntoFunctionSignature(callee, callSignature);
            g.mergeE(Map.of(
                    T.label, "CALLS",
                    Direction.from, callerV, Direction.to, calleeV
            ))
                    .option(Merge.onCreate, Map.of("is_computed", refType.isComputed()))
                    .iterate();
        }
    }

    private Vertex getConformingTypeOfWitness(Vertex witnessV) {
        return g.V(witnessV)
                .in("HAS_WITNESS")
                .in("HAS_PWT")
                .out("IS_A")
                .hasLabel("CLASS", "STRUCT").next();
    }

    private void applyDefaultCallingConventionForReturnType(VarnodeContext context, Instruction instr, Address output) {
        Varnode result = context.createConstantVarnode(output.getOffset(), 8);
        boolean isProtocolType = g.V().has("PROTOCOL", "address", result.getOffset()).hasNext();
        Varnode[] returnLocs = context.getReturnVarnode(null);

        Optional<Reference> indirectReturn = Arrays.stream(instr.getReferencesFrom())
                .filter(r -> r.isStackReference() && r.getReferenceType() == RefType.PARAM)
                .findAny();

        for (Varnode r : returnLocs) context.putValue(r, result, false);

        if (indirectReturn.isPresent()) {
            Address retAddr = indirectReturn.get().getToAddress();
            int stackSpace = context.getAddressSpace(context.getStackRegister().getName());
            Varnode retAddrV = context.getVarnode(
                   stackSpace, retAddr.getOffset(), 8);
            println("Function with indirect return at " + instr.getAddress() + " to " + retAddrV);
            if (isProtocolType) {
                createExistentialContainer(context, instr, retAddrV, result);
            } else {
                context.putValue(retAddrV, result, false);
            }
        }
        Reference ref = instr.getProgram().getReferenceManager().addMemoryReference(
                instr.getMaxAddress(), output,
                RefType.PARAM, SourceType.USER_DEFINED, 0);
    }

    private Address findSomePointerTo(Program program, Address address) {
        ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(address);
        Listing currentListing = program.getListing();
        while (refIter.hasNext()) {
            Reference ref = refIter.next();
            Data d = currentListing.getDataAt(ref.getFromAddress());

            if (d!= null && d.isPointer()) {
                return d.getAddress();
            }
        }
        return Address.NO_ADDRESS;
    }

    private Address findClassTOfFunction(Function f) {
        ReferenceIterator refIter = f.getProgram().getReferenceManager().getReferencesTo(f.getEntryPoint());
        Listing currentListing = f.getProgram().getListing();
        DataType dataTypeClassT = currentListing.getDataTypeManager().getDataType("/_objc2_/class_t");
        while (refIter.hasNext()) {
            Reference ref = refIter.next();
            Data d = currentListing.getDataAt(ref.getFromAddress());

            // filter global function list LC_FUNCTION_STARTS
            if (d != null && !d.isPointer()) continue;
            while (d != null && !d.getDataType().equals(dataTypeClassT)) {
                d = currentListing.getDefinedDataBefore(d.getAddress());
            }

            if (d != null) {
                return d.getAddress();
            }
        }
        return Address.NO_ADDRESS;
    }


    @Override
    public boolean evaluateContextBefore(VarnodeContext context, Instruction instr) {
        // if this instr is an entry point init register with typeRefs
        Function f = instr.getProgram().getFunctionManager().getFunctionAt(instr.getAddress());
        if(f != null && functionSignatures.containsKey(f)) {
            println("setting typerefs");
            Map<Register, Address> funcSignature = functionSignatures.get(f);
            AddressSpace memspace = instr.getProgram().getAddressFactory().getDefaultAddressSpace();
            for (Register r : funcSignature.keySet()) {
                if (funcSignature.get(r) == null) continue;
                context.setValue(r, BigInteger.valueOf(funcSignature.get(r).getOffset()));
            }
        }

        // test if it is a "self" call
        if (f != null) {
            Address classTAddr = findClassTOfFunction(f);
            if (classTAddr != Address.NO_ADDRESS) {
                println("  * class_t: " + classTAddr);
                Register x20 = context.getRegister("x20");
                context.setValue(x20, BigInteger.valueOf(classTAddr.getOffset()));
            }
        }
        if (instr.getFlowType().isCall()) {
            evaluateParameterBefore(context, instr);
        }
        return super.evaluateContextBefore(context, instr);
    }

    @Override
    public boolean evaluateContext(VarnodeContext context, Instruction instr) {
        // find stored reference to possible return type from evaluation of parameters before the instruction
        if (instr.getFlowType().isCall()) {
            for (Reference r : instr.getReferencesFrom()) {
                if (r.getReferenceType() == RefType.PARAM && graphContainsType(r.getToAddress())) {
                    applyDefaultCallingConventionForReturnType(context, instr, r.getToAddress());
                    break;
                }
            }
        } else if (Arrays.stream(instr.getPcode()).anyMatch(p -> p.getOpcode() == PcodeOp.LOAD)) {
            if (instr.getInputObjects().length == 1 && instr.getInputObjects()[0] instanceof Register x20) {
                if (Objects.equals(x20.getName(), "x20")) {
                    undoFirstLoad(context, instr, x20);
                }
            }
        }

        return super.evaluateContext(context, instr);
    }

    private void undoFirstLoad(VarnodeContext context, Instruction instr , Register register) {

        RegisterValue rval = context.getRegisterValue(register);
        Address addr = rval != null ?  instr.getAddress().getNewAddress(rval.getUnsignedValue().longValue())
                : Address.NO_ADDRESS;

        println("overwriting x20 currently: " + addr + " at " + instr.getAddress());

        Address ptr = findSomePointerTo(instr.getProgram(), addr);
        if (ptr.getOffset() != Address.NO_ADDRESS.getOffset()) {
            println("found " + ptr);
            context.setValue(register, BigInteger.valueOf(ptr.getOffset()));
        }
    }

    @Override
    public Address evaluateConstant(VarnodeContext context, Instruction instr, int pcodeop, Address constant, int size, DataType dataType, RefType refType) {
        if (graphContainsType(constant)) {
            return constant;
        }
        Address in = constant;
        try {
            Address resolved = resolveTypeCache(context, constant);
            println("Constant " + constant + " resolved to " + resolved);
            if (graphContainsType(resolved)) in = resolved;
        } catch (NotFoundException e) {
            println("Constant " + constant + " is not a type.");
        }
        return super.evaluateConstant(context, instr, pcodeop, in, size, dataType, refType);
    }

    @Override
    public boolean evaluateReference(VarnodeContext context, Instruction instr, int pcodeop, Address address, int size, DataType dataType, RefType refType) {
        if (refType.isCall()) {
            handleCalls(context, instr, refType, address);
        }

        return super.evaluateReference(context, instr, pcodeop, address, size, dataType, refType);
    }

    @Override
    public boolean evaluateDestination(VarnodeContext context, Instruction instruction) {
        FlowType flowType = instruction.getFlowType();
        if (flowType.isCall()) {
            println("Found call flow dest at 0x" + instruction.getAddress());
        }

        return super.evaluateDestination(context, instruction);
    }

    @Override
    public boolean evaluateReturn(Varnode retVN, VarnodeContext context, Instruction instruction) {
        println("handling return of " + retVN + " at " + instruction.getAddress());

        Function f = instruction.getProgram().getFunctionManager().getFunctionContaining(instruction.getAddress());
        AddressSpace memspace = instruction.getProgram().getAddressFactory().getDefaultAddressSpace();

        if (f != null && retVN.isRegister()) {
            RegisterValue rval = context.getRegisterValue(context.getRegister(retVN));
            if (rval != null) {
                Varnode rvar = context.getVarnode(memspace.getSpaceID(), rval.getUnsignedValue().longValue(), 8);
                if (graphContainsType(rvar.getAddress())) {
                    Address oldVal = functionReturnType.putIfAbsent(f, rvar.getAddress());
                    // if not absent
                    if (oldVal != null) {
                        Address newVal = functionReturnType.put(
                                f,
                                commonSuperType(instruction.getProgram(), List.of(oldVal, rvar.getAddress()))
                        );
                        if (newVal != null && oldVal.getOffset() != newVal.getOffset()) changedFunctions.add(f);
                    } else {
                        changedFunctions.add(f);
                    }

                }
            }
        }
        return super.evaluateReturn(retVN, context, instruction);
    }

    @Override
    public Long unknownValue(VarnodeContext context, Instruction instruction, Varnode node) {
        return super.unknownValue(context, instruction, node);
    }

    @Override
    public boolean evaluateSymbolicReference(VarnodeContext context, Instruction instr, Address address) {
        return super.evaluateSymbolicReference(context, instr, address);
    }
}
