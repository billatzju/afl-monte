/*
   american fuzzy lop++ - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com>,
              Adrian Herrera <adrian.herrera@anu.edu.au>,
              Michal Zalewski

   NGRAM previous location coverage comes from Adrian Herrera.

   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019-2024 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

 */

 #define AFL_LLVM_PASS

 #include "config.h"
 #include "debug.h"
 #include <stdio.h>
 #include <stdlib.h>
 #include <unistd.h>
 
 #include <list>
 #include <string>
 #include <fstream>
 #include <sys/time.h>
 
 #include "llvm/Config/llvm-config.h"
 #if LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR < 5
 typedef long double max_align_t;
 #endif
 
 #include "llvm/Pass.h"
 #if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
   #include "llvm/Passes/PassPlugin.h"
   #include "llvm/Passes/PassBuilder.h"
   #include "llvm/IR/PassManager.h"
 #else
   #include "llvm/IR/LegacyPassManager.h"
   #include "llvm/Transforms/IPO/PassManagerBuilder.h"
 #endif
 #include "llvm/IR/BasicBlock.h"
 #include "llvm/IR/Module.h"
 #include "llvm/Support/Debug.h"
 #include "llvm/Support/MathExtras.h"
 #if LLVM_VERSION_MAJOR >= 14                /* how about stable interfaces? */
   #include "llvm/Passes/OptimizationLevel.h"
 #endif
 
 #if LLVM_VERSION_MAJOR >= 4 || \
     (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR > 4)
   #include "llvm/IR/DebugInfo.h"
   #include "llvm/IR/CFG.h"
 #else
   #include "llvm/DebugInfo.h"
   #include "llvm/Support/CFG.h"
 #endif
 
 #include "llvm/IR/IRBuilder.h"
 
 #include "afl-llvm-common.h"
 #include "llvm-alternative-coverage.h"
 
 using namespace llvm;
 
 namespace {
 
 #if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
 class AFLCoverage : public PassInfoMixin<AFLCoverage> {
 
  public:
   AFLCoverage() {
 
 #else
 class AFLCoverage : public ModulePass {
 
  public:
   static char ID;
   AFLCoverage() : ModulePass(ID) {
 
 #endif
 
     initInstrumentList();
 
   }
 
 #if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
   PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
 #else
   bool runOnModule(Module &M) override;
 #endif
 
  protected:
   uint32_t    ngram_size = 0;
   uint32_t    ctx_k = 0;
   uint32_t    map_size = MAP_SIZE;
   uint32_t    function_minimum_size = 1;
   const char *ctx_str = NULL, *caller_str = NULL, *skip_nozero = NULL;
   const char *use_threadsafe_counters = nullptr;
 
 };
 
 }  // namespace
 
 #if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
 extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
 
   return {LLVM_PLUGIN_API_VERSION, "AFLCoverage", "v0.1",
           /* lambda to insert our pass into the pass pipeline. */
           [](PassBuilder &PB) {
 
   #if 1
     #if LLVM_VERSION_MAJOR <= 13
             using OptimizationLevel = typename PassBuilder::OptimizationLevel;
     #endif
     #if LLVM_VERSION_MAJOR >= 16
       #if LLVM_VERSION_MAJOR >= 20
             PB.registerPipelineStartEPCallback(
       #else
             PB.registerOptimizerEarlyEPCallback(
       #endif
     #else
             PB.registerOptimizerLastEPCallback(
     #endif
                 [](ModulePassManager &MPM, OptimizationLevel OL) {
 
                   MPM.addPass(AFLCoverage());
 
                 });
 
   /* TODO LTO registration */
   #else
             using PipelineElement = typename PassBuilder::PipelineElement;
             PB.registerPipelineParsingCallback([](StringRef          Name,
                                                   ModulePassManager &MPM,
                                                   ArrayRef<PipelineElement>) {
 
               if (Name == "AFLCoverage") {
 
                 MPM.addPass(AFLCoverage());
                 return true;
 
               } else {
 
                 return false;
 
               }
 
             });
 
   #endif
 
           }};
 
 }
 
 #else
 
 char AFLCoverage::ID = 0;
 #endif
 
 /* needed up to 3.9.0 */
 #if LLVM_VERSION_MAJOR == 3 && \
     (LLVM_VERSION_MINOR < 9 || \
      (LLVM_VERSION_MINOR == 9 && LLVM_VERSION_PATCH < 1))
 uint64_t PowerOf2Ceil(unsigned in) {
 
   uint64_t in64 = in - 1;
   in64 |= (in64 >> 1);
   in64 |= (in64 >> 2);
   in64 |= (in64 >> 4);
   in64 |= (in64 >> 8);
   in64 |= (in64 >> 16);
   in64 |= (in64 >> 32);
   return in64 + 1;
 
 }
 
 #endif
 
 /* #if LLVM_VERSION_STRING >= "4.0.1" */
 #if LLVM_VERSION_MAJOR >= 5 || \
     (LLVM_VERSION_MAJOR == 4 && LLVM_VERSION_PATCH >= 1)
   #define AFL_HAVE_VECTOR_INTRINSICS 1
 #endif
 
 #if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
 PreservedAnalyses AFLCoverage::run(Module &M, ModuleAnalysisManager &MAM) {
 
 #else
 bool AFLCoverage::runOnModule(Module &M) {
 
 #endif
 
   LLVMContext &C = M.getContext();
 
   IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
   IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
 #ifdef AFL_HAVE_VECTOR_INTRINSICS
   IntegerType *IntLocTy =
       IntegerType::getIntNTy(C, sizeof(PREV_LOC_T) * CHAR_BIT);
 #endif
   struct timeval  tv;
   struct timezone tz;
   u32             rand_seed;
   unsigned int    cur_loc = 0;
 
   /* Setup random() so we get Actually Random(TM) outputs from AFL_R() */
   gettimeofday(&tv, &tz);
   rand_seed = tv.tv_sec ^ tv.tv_usec ^ getpid();
   AFL_SR(rand_seed);
 
   /* Show a banner */
 
   setvbuf(stdout, NULL, _IONBF, 0);
 
   if (getenv("AFL_DEBUG")) debug = 1;
 
 #if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
   if (getenv("AFL_SAN_NO_INST")) {
 
     if (debug) { fprintf(stderr, "Instrument disabled\n"); }
     return PreservedAnalyses::all();
 
   }
 
 #else
   if (getenv("AFL_SAN_NO_INST")) {
 
     if (debug) { fprintf(stderr, "Instrument disabled\n"); }
     return true; // Module was not modified in old pass manager style
 
   }
 
 #endif
 
   if ((isatty(2) && !getenv("AFL_QUIET")) || getenv("AFL_DEBUG") != NULL) {
 
     SAYF(cCYA "afl-llvm-pass" VERSION cRST
               " by <lszekeres@google.com> and <adrian.herrera@anu.edu.au>\n");
 
   } else
 
     be_quiet = 1;
 
   char        *inst_ratio_str = getenv("AFL_INST_RATIO");
   unsigned int inst_ratio = 100;
 
   if (inst_ratio_str) {
 
     if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
         inst_ratio > 100)
       FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");
 
   }
 
 #if LLVM_VERSION_MAJOR < 9
   // char *neverZero_counters_str = getenv("AFL_LLVM_NOT_ZERO"); // This was for an older mechanism
 #endif
   skip_nozero = getenv("AFL_LLVM_SKIP_NEVERZERO");
   use_threadsafe_counters = getenv("AFL_LLVM_THREADSAFE_INST");
 
   if ((isatty(2) && !getenv("AFL_QUIET")) || !!getenv("AFL_DEBUG")) {
     if (use_threadsafe_counters) {
       skip_nozero = "1"; // Threadsafe implies not-zero for some older logic, ensure consistency or remove if not needed.
       SAYF(cCYA "afl-llvm-pass" VERSION cRST " using thread safe counters\n");
     } else {
       SAYF(cCYA "afl-llvm-pass" VERSION cRST
                 " using non-thread safe instrumentation\n");
     }
   }
 
   unsigned PrevLocSize = 0;
   unsigned PrevCallerSize = 0;
 
   char *ngram_size_str = getenv("AFL_LLVM_NGRAM_SIZE");
   if (!ngram_size_str) ngram_size_str = getenv("AFL_NGRAM_SIZE");
   char *ctx_k_str = getenv("AFL_LLVM_CTX_K");
   if (!ctx_k_str) ctx_k_str = getenv("AFL_CTX_K");
   ctx_str = getenv("AFL_LLVM_CTX");
   caller_str = getenv("AFL_LLVM_CALLER");
 
   bool instrument_ctx = ctx_str || caller_str;
 
 #ifdef AFL_HAVE_VECTOR_INTRINSICS
   VectorType *PrevLocTy = NULL;
   if (ngram_size_str)
     if (sscanf(ngram_size_str, "%u", &ngram_size) != 1 || ngram_size < 2 ||
         ngram_size > NGRAM_SIZE_MAX)
       FATAL(
           "Bad value of AFL_NGRAM_SIZE (must be between 2 and NGRAM_SIZE_MAX "
           "(%u))",
           NGRAM_SIZE_MAX);
   if (ngram_size == 1) ngram_size = 0; // Ngram 1 is just standard edge coverage
   if (ngram_size)
     PrevLocSize = ngram_size - 1;
   else
     PrevLocSize = 1; // For the scalar __afl_prev_loc
 
   VectorType *PrevCallerTy = NULL;
   if (ctx_k_str)
     if (sscanf(ctx_k_str, "%u", &ctx_k) != 1 || ctx_k < 1 || ctx_k > CTX_MAX_K)
       FATAL("Bad value of AFL_CTX_K (must be between 1 and CTX_MAX_K (%u))",
             CTX_MAX_K);
   if (ctx_k == 1 && !caller_str) { // If K=1 and not explicitly using caller_str, it might mean simple context
     ctx_k = 0; // Disable k-context vector
     instrument_ctx = true; // Keep simple context flag if ctx_str was set
     // If ctx_k_str was "1", and neither ctx_str nor caller_str were set, this might need review
     // For now, assume if ctx_k_str is "1", it means simple context or caller context.
     if (!ctx_str) caller_str = "1"; // Enable simple caller context if only K=1 was given
   }
   if (ctx_k) {
     PrevCallerSize = ctx_k;
     instrument_ctx = true;
   }
 #else
   if (ngram_size_str)
     FATAL("NGRAM coverage requires LLVM build with vector intrinsic support.");
   if (ctx_k_str)
     FATAL("K-CTX coverage requires LLVM build with vector intrinsic support.");
   PrevLocSize = 1; // For scalar __afl_prev_loc
   ngram_size = 0;  // Ensure ngram_size is 0 if no vector intrinsics
   ctx_k = 0;       // Ensure ctx_k is 0
 #endif
 
   Type* ActualPrevLocTy = Int32Ty; // Default for scalar
 #ifdef AFL_HAVE_VECTOR_INTRINSICS
   int PrevLocVecSize = PowerOf2Ceil(PrevLocSize);
   if (ngram_size) {
     PrevLocTy = VectorType::get(IntLocTy, PrevLocVecSize
   #if LLVM_VERSION_MAJOR >= 12
                                 , false // isScalable
   #endif
     );
     ActualPrevLocTy = PrevLocTy;
   }
 #endif
 
   Type* ActualPrevCallerTy = Int32Ty; // Default for scalar
 #ifdef AFL_HAVE_VECTOR_INTRINSICS
   int PrevCallerVecSize = PowerOf2Ceil(PrevCallerSize);
   if (ctx_k) {
     PrevCallerTy = VectorType::get(IntLocTy, PrevCallerVecSize
   #if LLVM_VERSION_MAJOR >= 12
                                    , false // isScalable
   #endif
     );
     ActualPrevCallerTy = PrevCallerTy;
   }
 #endif
 
   GlobalVariable *AFLMapPtr =
       new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                          GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");
   GlobalVariable *AFLPrevLoc;
   GlobalVariable *AFLPrevCaller;
   GlobalVariable *AFLContext = NULL;
 
   if (ctx_str || caller_str || ctx_k) { // If any form of context is enabled
 #if defined(__ANDROID__) || defined(__HAIKU__) || defined(NO_TLS)
     AFLContext = new GlobalVariable(
         M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_ctx");
 #else
     AFLContext = new GlobalVariable(
         M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_ctx", nullptr,
         GlobalVariable::GeneralDynamicTLSModel, 0, false);
 #endif
   }
 
 #if defined(__ANDROID__) || defined(__HAIKU__) || defined(NO_TLS)
   AFLPrevLoc = new GlobalVariable(
       M, ActualPrevLocTy, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc");
   AFLPrevCaller = new GlobalVariable(
       M, ActualPrevCallerTy, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_caller");
 #else
   AFLPrevLoc = new GlobalVariable(
       M, ActualPrevLocTy, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc", nullptr,
       GlobalVariable::GeneralDynamicTLSModel, 0, false);
   AFLPrevCaller = new GlobalVariable(
       M, ActualPrevCallerTy, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_caller", nullptr,
       GlobalVariable::GeneralDynamicTLSModel, 0, false);
 #endif
 
   // --- START: Add declaration for __afl_log_transition ---
   FunctionCallee LogTransFunc = M.getOrInsertFunction(
       "__afl_log_transition", Type::getVoidTy(C), Int32Ty, Int32Ty);
   // --- END: Add declaration for __afl_log_transition ---
 
 
 #ifdef AFL_HAVE_VECTOR_INTRINSICS
   Constant *PrevLocShuffleMask = nullptr;
   if (ngram_size) {
     SmallVector<Constant *, 32> PrevLocShuffle = {UndefValue::get(Int32Ty)};
     for (unsigned I = 0; I < PrevLocSize - 1; ++I)
       PrevLocShuffle.push_back(ConstantInt::get(Int32Ty, I));
     for (unsigned I = PrevLocSize -1; I < (unsigned)PrevLocVecSize -1; ++I) // Fill remaining if VecSize > Size
       PrevLocShuffle.push_back(ConstantInt::get(Int32Ty, PrevLocSize -1 )); // Pad with last valid index
      PrevLocShuffleMask = ConstantVector::get(PrevLocShuffle);
   }
 
   Constant *PrevCallerShuffleMask = nullptr;
   if (ctx_k) {
     SmallVector<Constant *, 32> PrevCallerShuffle = {UndefValue::get(Int32Ty)};
     for (unsigned I = 0; I < PrevCallerSize - 1; ++I)
       PrevCallerShuffle.push_back(ConstantInt::get(Int32Ty, I));
     for (unsigned I = PrevCallerSize-1; I < (unsigned)PrevCallerVecSize-1; ++I)
       PrevCallerShuffle.push_back(ConstantInt::get(Int32Ty, PrevCallerSize-1));
     PrevCallerShuffleMask = ConstantVector::get(PrevCallerShuffle);
   }
 #endif
 
   ConstantInt *One = ConstantInt::get(Int8Ty, 1);
   Value    *PrevCtxVal = nullptr;     
   LoadInst *PrevCallerLoad = nullptr;  
 
   int inst_blocks = 0;
   scanForDangerousFunctions(&M);
 
   for (auto &F : M) {
     int has_calls = 0;
     if (debug)
       fprintf(stderr, "FUNCTION: %s (%zu)\n", F.getName().str().c_str(),
               F.size());
 
     if (!isInInstrumentList(&F, M.getName().str())) { continue; } // M.getName() for module name if needed by isInInstrumentList
 
     if (F.size() < function_minimum_size) { continue; }
 
     for (auto &BB : F) {
       BasicBlock::iterator IP = BB.getFirstInsertionPt();
       IRBuilder<>          IRB(&(*IP));
 
       if (instrument_ctx && &BB == &F.getEntryBlock()) {
 #ifdef AFL_HAVE_VECTOR_INTRINSICS
         if (ctx_k) {
           PrevCallerLoad = IRB.CreateLoad(ActualPrevCallerTy, AFLPrevCaller);
           PrevCallerLoad->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
           PrevCtxVal = IRB.CreateZExt(IRB.CreateXorReduce(PrevCallerLoad), Int32Ty);
         } else
 #endif
         if (AFLContext) { // Only if simple context (ctx_str or caller_str) is enabled
           LoadInst *PrevCtxLoadInst = IRB.CreateLoad(Int32Ty, AFLContext);
           PrevCtxLoadInst->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
           PrevCtxVal = PrevCtxLoadInst;
         }
 
         if (PrevCtxVal) { // Check if context is being used
             for (auto &BB_2 : F) {
                 if (has_calls) break;
                 for (auto &IN : BB_2) {
                     CallInst *callInst = nullptr;
                     if ((callInst = dyn_cast<CallInst>(&IN))) {
                         Function *Callee = callInst->getCalledFunction();
                         if (!Callee || Callee->isDeclaration() || Callee->size() < function_minimum_size || isIgnoreFunction(Callee))
                             continue;
                         else { has_calls = 1; break; }
                     }
                 }
             }
         }
 
         if (has_calls && AFLContext) {
           Value *NewCtx = ConstantInt::get(Int32Ty, AFL_R(map_size));
 #ifdef AFL_HAVE_VECTOR_INTRINSICS
           if (ctx_k && PrevCallerLoad) { // Ensure PrevCallerLoad is valid
             Value *ShuffledPrevCaller = IRB.CreateShuffleVector(
                 PrevCallerLoad, UndefValue::get(ActualPrevCallerTy), // Use ActualPrevCallerTy
                 PrevCallerShuffleMask);
             Value *UpdatedPrevCaller = IRB.CreateInsertElement(
                 ShuffledPrevCaller, IRB.CreateZExtOrTrunc(NewCtx, IntLocTy), (uint64_t)0); // Ensure type match for insert
             StoreInst *Store = IRB.CreateStore(UpdatedPrevCaller, AFLPrevCaller);
             Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
           } else
 #endif
           if (PrevCtxVal) { // Simple context
             if (ctx_str) NewCtx = IRB.CreateXor(PrevCtxVal, NewCtx);
             StoreInst *StoreCtx = IRB.CreateStore(NewCtx, AFLContext);
             StoreCtx->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
           }
         }
       }
 
       if (AFL_R(100) >= inst_ratio) continue;
 
 #if !(LLVM_VERSION_MAJOR == 6 && LLVM_VERSION_MINOR == 0) || !defined __linux__
       int more_than_one_pred_successor = -1;
       if (F.size() > 1) { // Only apply optimization if function has more than one BB
         for (BasicBlock *Pred : predecessors(&BB)) {
           if (more_than_one_pred_successor == -1) more_than_one_pred_successor = 0;
           if (Pred->getTerminator()->getNumSuccessors() > 1) {
             more_than_one_pred_successor = 1;
             break;
           }
         }
       }
       if (F.size() > 1 && more_than_one_pred_successor != 1) {
         if (instrument_ctx && has_calls && AFLContext && PrevCtxVal) {
           Instruction *Term = BB.getTerminator();
           if (isa<ReturnInst>(Term) || isa<ResumeInst>(Term)) {
             IRBuilder<> Post_IRB(Term);
             StoreInst *RestoreCtx;
 #ifdef AFL_HAVE_VECTOR_INTRINSICS
             if (ctx_k && PrevCallerLoad) RestoreCtx = Post_IRB.CreateStore(PrevCallerLoad, AFLPrevCaller);
             else
 #endif
             RestoreCtx = Post_IRB.CreateStore(PrevCtxVal, AFLContext);
             RestoreCtx->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
           }
         }
         continue;
       }
 #endif
 
       cur_loc = AFL_R(map_size);
       ConstantInt *CurLocConst = ConstantInt::get(ngram_size ? IntLocTy : Int32Ty, cur_loc);
 
       LoadInst *PrevLocLoad = IRB.CreateLoad(ActualPrevLocTy, AFLPrevLoc);
       PrevLocLoad->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
       
       Value *PrevLocValForMapIdx;
 #ifdef AFL_HAVE_VECTOR_INTRINSICS
       if (ngram_size)
         PrevLocValForMapIdx = IRB.CreateZExt(IRB.CreateXorReduce(PrevLocLoad), Int32Ty);
       else
 #endif
         PrevLocValForMapIdx = PrevLocLoad; // Already Int32Ty if not ngram
 
       if (instrument_ctx && PrevCtxVal) {
         PrevLocValForMapIdx = IRB.CreateXor(PrevLocValForMapIdx, PrevCtxVal);
       }
       // Ensure PrevLocValForMapIdx is Int32Ty for XORing with CurLocConst (if CurLocConst is Int32Ty)
       if (PrevLocValForMapIdx->getType() != Int32Ty) {
           PrevLocValForMapIdx = IRB.CreateZExtOrTrunc(PrevLocValForMapIdx, Int32Ty);
       }
       Value* CurLocForMapIdx = IRB.CreateZExtOrTrunc(CurLocConst, Int32Ty);
 
 
       // --- START: Insert call to __afl_log_transition ---
       Value *PrevLocForLog;
 #ifdef AFL_HAVE_VECTOR_INTRINSICS
       if (ngram_size) {
           Value* Elem0 = IRB.CreateExtractElement(PrevLocLoad, ConstantInt::get(Int32Ty, 0));
           PrevLocForLog = IRB.CreateZExtOrTrunc(Elem0, Int32Ty);
       } else
 #endif
       { PrevLocForLog = PrevLocLoad; } // Already Int32Ty
 
       Value *CurLocShiftedForLog;
 #ifdef AFL_HAVE_VECTOR_INTRINSICS
       if (ngram_size) {
           CurLocShiftedForLog = IRB.CreateLShr(CurLocConst, ConstantInt::get(IntLocTy, 1));
           CurLocShiftedForLog = IRB.CreateZExtOrTrunc(CurLocShiftedForLog, Int32Ty);
       } else
 #endif
       { CurLocShiftedForLog = ConstantInt::get(Int32Ty, cur_loc >> 1); }
       
       IRB.CreateCall(LogTransFunc, {PrevLocForLog, CurLocShiftedForLog});
       // --- END: Insert call to __afl_log_transition ---
 
 
       LoadInst *MapPtr = IRB.CreateLoad(PointerType::get(Int8Ty, 0), AFLMapPtr);
       MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
 
       Value *MapPtrIdx = IRB.CreateGEP(
 #if LLVM_VERSION_MAJOR >= 14
           Int8Ty,
 #endif
           MapPtr, IRB.CreateXor(PrevLocValForMapIdx, CurLocForMapIdx));
 
       if (use_threadsafe_counters) {                              
         IRB.CreateAtomicRMW(llvm::AtomicRMWInst::BinOp::Add, MapPtrIdx, One,
 #if LLVM_VERSION_MAJOR >= 13
                             llvm::MaybeAlign(1),
 #endif
                             llvm::AtomicOrdering::Monotonic);
       } else {
         LoadInst *Counter = IRB.CreateLoad(Int8Ty, MapPtrIdx);
         Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
         Value *Incr = IRB.CreateAdd(Counter, One);
 #if LLVM_VERSION_MAJOR >= 9
         if (!skip_nozero) {
 #else
         // if (neverZero_counters_str != NULL) { // This was the old check
         if (!skip_nozero) { // Align with newer logic
 #endif
           ConstantInt *Zero = ConstantInt::get(Int8Ty, 0);
           auto         cf = IRB.CreateICmpEQ(Incr, Zero);
           auto         carry = IRB.CreateZExt(cf, Int8Ty);
           Incr = IRB.CreateAdd(Incr, carry);
         }
         IRB.CreateStore(Incr, MapPtrIdx)
             ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
       }                                                  
 
       StoreInst *StoreNewPrevLoc;
 #ifdef AFL_HAVE_VECTOR_INTRINSICS
       if (ngram_size) {
         Value *ShiftedCurLoc = IRB.CreateLShr(CurLocConst, ConstantInt::get(IntLocTy, 1));
         Value *ShuffledPrevLoc = IRB.CreateShuffleVector(
             PrevLocLoad, UndefValue::get(ActualPrevLocTy), PrevLocShuffleMask);
         Value *UpdatedPrevLoc = IRB.CreateInsertElement(
             ShuffledPrevLoc, ShiftedCurLoc, (uint64_t)0);
         StoreNewPrevLoc = IRB.CreateStore(UpdatedPrevLoc, AFLPrevLoc);
       } else
 #endif
       {
         StoreNewPrevLoc = IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
       }
       StoreNewPrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
 
       if (instrument_ctx && has_calls && AFLContext && PrevCtxVal) {
         Instruction *Term = BB.getTerminator();
         if (isa<ReturnInst>(Term) || isa<ResumeInst>(Term)) {
           IRBuilder<> Post_IRB(Term);
           StoreInst *RestoreCtx;
 #ifdef AFL_HAVE_VECTOR_INTRINSICS
           if (ctx_k && PrevCallerLoad) RestoreCtx = Post_IRB.CreateStore(PrevCallerLoad, AFLPrevCaller);
           else
 #endif
           RestoreCtx = Post_IRB.CreateStore(PrevCtxVal, AFLContext);
           RestoreCtx->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
         }
       }
       inst_blocks++;
     }
   }
 
   if (!be_quiet) {
     if (!inst_blocks)
       WARNF("No instrumentation targets found.");
     else {
       char modeline[100];
       snprintf(modeline, sizeof(modeline), "%s%s%s%s%s%s",
                getenv("AFL_HARDEN") ? "hardened" : "non-hardened",
                getenv("AFL_USE_ASAN") ? ", ASAN" : "",
                getenv("AFL_USE_MSAN") ? ", MSAN" : "",
                getenv("AFL_USE_CFISAN") ? ", CFISAN" : "",
                getenv("AFL_USE_TSAN") ? ", TSAN" : "",
                getenv("AFL_USE_UBSAN") ? ", UBSAN" : "");
       OKF("Instrumented %d locations (%s mode, ratio %u%%).", inst_blocks,
           modeline, inst_ratio);
     }
   }
 
 #if LLVM_VERSION_MAJOR >= 11                        
   return PreservedAnalyses::allInSet<CFGAnalyses>(); // Indicate CFG might have changed if blocks were split, otherwise PreservedAnalyses::all()
 #else
   return true; // Indicate module was modified
 #endif
 }
 
 #if LLVM_VERSION_MAJOR < 11                         /* use old pass manager */
 static void registerAFLPass(const PassManagerBuilder &,
                             legacy::PassManagerBase &PM) {
   PM.add(new AFLCoverage());
 }
 
 static RegisterStandardPasses RegisterAFLPass(
     PassManagerBuilder::EP_OptimizerLast, registerAFLPass);
 
 static RegisterStandardPasses RegisterAFLPass0(
     PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);
 #endif
 