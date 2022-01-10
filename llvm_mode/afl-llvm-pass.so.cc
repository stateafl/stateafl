/*
  Copyright 2015 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.
*/

#define AFL_LLVM_PASS

#include "../config.h"
#include "../debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include "llvm/IR/DataLayout.h"

#include <cxxabi.h>

#include "state-tracer.h"

using namespace llvm;

namespace {

  class AFLCoverage : public ModulePass {

    public:

      static char ID;
      AFLCoverage() : ModulePass(ID) { }

      bool runOnModule(Module &M) override;

      // StringRef getPassName() const override {
      //  return "American Fuzzy Lop Instrumentation";
      // }

  };

}


char AFLCoverage::ID = 0;


bool AFLCoverage::runOnModule(Module &M) {

  LLVMContext &C = M.getContext();

  IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);

  /* Show a banner */

  char be_quiet = 0;

  if (isatty(2) && !getenv("AFL_QUIET")) {

    SAYF(cCYA "afl-llvm-pass " cBRI VERSION cRST " by <lszekeres@google.com>\n");

  } else be_quiet = 1;

  /* Decide instrumentation ratio */

  char* inst_ratio_str = getenv("AFL_INST_RATIO");
  unsigned int inst_ratio = 100;

  if (inst_ratio_str) {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");

  }

  /* Get globals for the SHM region and the previous location. Note that
     __afl_prev_loc is thread-local. */

  GlobalVariable *AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

  GlobalVariable *AFLPrevLoc = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc",
      0, GlobalVariable::GeneralDynamicTLSModel, 0, false);

  /* Get list of user-defined primitives for sending/receiving data */

  char* trace_custom_receive = getenv("TRACE_CUSTOM_RECEIVE");
  char* trace_custom_send = getenv("TRACE_CUSTOM_SEND");

  std::map<StringRef, int> map_custom_receive;
  std::map<StringRef, int> map_custom_send;

  if (trace_custom_receive) {

    StringRef custom_list = trace_custom_receive;
    std::pair<StringRef, StringRef> splitted;

    do {
 
      splitted = custom_list.split(';');

      if(splitted.first != "") {

        std::pair<StringRef, StringRef> item = splitted.first.split(':');

        StringRef func_name = item.first;
        int param_pos;
        
        if(item.second.empty()) {
          param_pos = -1;
        } else {
          param_pos = atoi(std::string(item.second).c_str());
        }

        map_custom_receive.insert( std::pair<StringRef,int>(func_name, param_pos) );

        OKF("INSTRUMENTING CUSTOM RECEIVE '%s'\n", std::string(splitted.first).c_str());
      }

      custom_list = splitted.second;

    } while( custom_list != "");
  }

  if (trace_custom_send) {

    StringRef custom_list = trace_custom_send;
    std::pair<StringRef, StringRef> splitted;

    do {
 
      splitted = custom_list.split(';');

      if(splitted.first != "") {

        std::pair<StringRef, StringRef> item = splitted.first.split(':');

        StringRef func_name = item.first;
        int param_pos;
        
        if(item.second.empty()) {
          param_pos = -1;
        } else {
          param_pos = atoi(std::string(item.second).c_str());
        }

        map_custom_send.insert( std::pair<StringRef,int>(func_name, param_pos) );

        OKF("INSTRUMENTING CUSTOM SEND '%s'\n", std::string(splitted.first).c_str());
      }

      custom_list = splitted.second;

    } while( custom_list != "");
  }


  /* Instrument all the things! */

  int inst_blocks = 0;

  for (auto &F : M) {

    SmallVector<CallInst*, 16> stack_lookups;
  
    for (auto &BB : F) {

      BasicBlock::iterator IP = BB.getFirstInsertionPt();
      IRBuilder<> IRB(&(*IP));

      if (AFL_R(100) >= inst_ratio) continue;

      /* Make up cur_loc */

      unsigned int cur_loc = AFL_R(MAP_SIZE);

      ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

      /* Load prev_loc */

      LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
      PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

      /* Load SHM pointer */

      LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
      MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *MapPtrIdx =
          IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevLocCasted, CurLoc));

      /* Update bitmap */

      LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
      Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
      IRB.CreateStore(Incr, MapPtrIdx)
          ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      /* Set prev_loc to cur_loc >> 1 */

      StoreInst *Store =
          IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
      Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      inst_blocks++;



      for(BasicBlock::iterator it = BB.begin(); it != BB.end(); it++) {

        /*
        AllocaInst * alloca_inst = dyn_cast<AllocaInst>(it);

        if(alloca_inst != nullptr) {

          if( alloca_inst->getAllocatedType()->isStructTy() ) {

            auto alloc_size = alloca_inst->getAllocationSizeInBits(M.getDataLayout()).getValue();

            auto debugInfo = alloca_inst->getDebugLoc();
            //OKF("Found stack allocation: %s:%d (%lu bytes)\n", debugInfo->getFilename().data(), debugInfo->getLine(), alloc_size*8);
            OKF("Found stack allocation (%lu bytes)\n", alloc_size/8);
          }
        }
        */

        CallInst * call_instr = dyn_cast<CallInst>(it);

        if(call_instr == nullptr)
          continue;
        
        auto called_func = call_instr->getCalledFunction();
        if (called_func == nullptr)
          continue;


        std::string demangled;
        int demangled_status;
        char * demangled_char = abi::__cxa_demangle(called_func->getName().data(), nullptr, nullptr, &demangled_status);

        if(demangled_status == 0) {
          demangled = demangled_char;
        }

        if ( called_func->getName().startswith("llvm.lifetime") ) {
          OKF("FUNCTION LLVM: %s", called_func->getName().data() );

          stack_lookups.push_back(call_instr);
        }
        else
        if ( called_func->getName() == "malloc" || demangled.find("operator new") != std::string::npos ) {
          OKF("Found function call: %s\n", called_func->getName().data());

          if(demangled_status==0)
            OKF("DEMANGLED FUNCTION: %s\n", demangled.c_str());

          auto * voidTy = Type::getVoidTy(M.getContext());
          auto * int8PtrTy = Type::getInt8PtrTy(M.getContext());
          auto * int32Ty = Type::getInt32Ty(M.getContext());

          auto * helperTy = FunctionType::get(voidTy, int8PtrTy, int32Ty);
          auto helper_malloc = M.getOrInsertFunction("new_heap_alloc_record", helperTy);

          IRBuilder<> builder(call_instr);
          builder.SetInsertPoint(call_instr->getNextNode());
          builder.CreateCall(helper_malloc, {call_instr, call_instr->getOperand(0)});

        }
        if ( called_func->getName() == "calloc" ) {
          OKF("Found function call: %s\n", called_func->getName().data());

          auto * voidTy = Type::getVoidTy(M.getContext());
          auto * int8PtrTy = Type::getInt8PtrTy(M.getContext());
          auto * int32Ty = Type::getInt32Ty(M.getContext());

          auto * helperTy = FunctionType::get(voidTy, {int8PtrTy, int32Ty, int32Ty}, false);
          auto helper_malloc = M.getOrInsertFunction("trace_calloc", helperTy);

          IRBuilder<> builder(call_instr);
          builder.SetInsertPoint(call_instr->getNextNode());
          builder.CreateCall(helper_malloc, {call_instr, call_instr->getOperand(1), call_instr->getOperand(0)});

        }
        if ( called_func->getName() == "realloc" ) {
          OKF("Found function call: %s\n", called_func->getName().data());

          auto * voidTy = Type::getVoidTy(M.getContext());
          auto * int8PtrTy = Type::getInt8PtrTy(M.getContext());
          auto * int32Ty = Type::getInt32Ty(M.getContext());

          auto * helperTy = FunctionType::get(voidTy, {int8PtrTy, int32Ty, int8PtrTy}, false);
          auto helper_malloc = M.getOrInsertFunction("trace_realloc", helperTy);

          IRBuilder<> builder(call_instr);
          builder.SetInsertPoint(call_instr->getNextNode());
          builder.CreateCall(helper_malloc, {call_instr, call_instr->getOperand(1), call_instr->getOperand(0)});

        }
        else if ( called_func->getName() == "free" || demangled.find("operator delete") != std::string::npos ) {
          OKF("Found function call: %s\n", called_func->getName().data());

          if(demangled_status==0)
            OKF("DEMANGLED FUNCTION: %s\n", demangled.c_str());

          auto * voidTy = Type::getVoidTy(M.getContext());
          auto * int8PtrTy = Type::getInt8PtrTy(M.getContext());

          auto * helperTy = FunctionType::get(voidTy, int8PtrTy);
          auto helper_free = M.getOrInsertFunction("free_heap_alloc_record", helperTy);

          IRBuilder<> builder(call_instr);
          builder.CreateCall(helper_free, {call_instr->getOperand(0)});

        }
        else if(  called_func->getName() == "recv"
               || called_func->getName() == "recvfrom" )
        {
          OKF("Found function call: %s\n", called_func->getName().data());

          auto * voidTy = Type::getVoidTy(M.getContext());
          auto * int8PtrTy = Type::getInt8PtrTy(M.getContext()); /* pass buffer address */
          auto * int32Ty = Type::getInt32Ty(M.getContext()); /* pass buffer size */

          auto * helperTy = FunctionType::get(voidTy, int8PtrTy, int32Ty);
          auto helper = M.getOrInsertFunction("trace_receive", helperTy);

          IRBuilder<> builder(call_instr);
          builder.CreateCall(helper, {call_instr->getOperand(1), call_instr->getOperand(2)});

        }
        else if( called_func->getName() == "recvmsg" )
        {
          OKF("Found function call: %s\n", called_func->getName().data());

          auto * voidTy = Type::getVoidTy(M.getContext());
          auto * int8PtrTy = Type::getInt8PtrTy(M.getContext()); /* pass buffer address */
          auto * int32Ty = Type::getInt32Ty(M.getContext()); /* pass buffer size */

          auto * helperTy = FunctionType::get(voidTy, int8PtrTy, int32Ty);
          auto helper = M.getOrInsertFunction("trace_receive", helperTy);

          Value * buf_size;
          int struct_size;
          Type * T = call_instr->getOperand(1)->getType();

          if( !T->isPointerTy() || !T->getContainedType(0)->isStructTy() ) {

            WARNF("Error in recvmsg(): non-pointer input parameter\n");
            continue;
          }

          Type * PT = T->getContainedType(0);
          llvm::DataLayout* dl = new llvm::DataLayout(&M);
          struct_size = dl->getTypeAllocSize(PT);

          //WARNF("Type %s size: %d\n", PT->getStructName().data(), struct_size);

          buf_size = llvm::ConstantInt::get(int32Ty, struct_size, true);

          IRBuilder<> builder(call_instr);
          builder.CreateCall(helper, {call_instr->getOperand(1), buf_size});

        }
        else if(  called_func->getName() == "send" 
               || called_func->getName() == "sendto" )
        {
          OKF("Found function call: %s\n", called_func->getName().data());

          auto * voidTy = Type::getVoidTy(M.getContext());
          auto * int8PtrTy = Type::getInt8PtrTy(M.getContext()); /* pass buffer address */
          auto * int32Ty = Type::getInt32Ty(M.getContext()); /* pass buffer size */

          auto * helperTy = FunctionType::get(voidTy, int8PtrTy, int32Ty);
          auto helper = M.getOrInsertFunction("trace_send", helperTy);

          IRBuilder<> builder(call_instr);
          builder.CreateCall(helper, {call_instr->getOperand(1), call_instr->getOperand(2)});

        }
        else if(  called_func->getName() == "sendmsg" )
        {
          OKF("Found function call: %s\n", called_func->getName().data());

          auto * voidTy = Type::getVoidTy(M.getContext());
          auto * int8PtrTy = Type::getInt8PtrTy(M.getContext()); /* pass buffer address */
          auto * int32Ty = Type::getInt32Ty(M.getContext()); /* pass buffer size */

          auto * helperTy = FunctionType::get(voidTy, int8PtrTy, int32Ty);
          auto helper = M.getOrInsertFunction("trace_send", helperTy);

          Value * buf_size;
          int struct_size;
          Type * T = call_instr->getOperand(1)->getType();

          if( !T->isPointerTy() || !T->getContainedType(0)->isStructTy() ) {

            WARNF("Error in sendmsg(): non-pointer input parameter\n");
            continue;
          }

          Type * PT = T->getContainedType(0);
          llvm::DataLayout* dl = new llvm::DataLayout(&M);
          struct_size = dl->getTypeAllocSize(PT);

          //WARNF("Type %s size: %d\n", PT->getStructName().data(), struct_size);

          buf_size = llvm::ConstantInt::get(int32Ty, struct_size, true);

          IRBuilder<> builder(call_instr);
          builder.CreateCall(helper, {call_instr->getOperand(1), buf_size});

        }
        else if(   map_custom_receive.count(called_func->getName().data()) 
                || map_custom_send.count(called_func->getName()) )
        {
          OKF("Found function call: %s\n", called_func->getName().data());

          auto * voidTy = Type::getVoidTy(M.getContext());
          auto * int8PtrTy = Type::getInt8PtrTy(M.getContext()); /* pass buffer address */
          auto * int32Ty = Type::getInt32Ty(M.getContext()); /* pass buffer size */

          auto * helperTy = FunctionType::get(voidTy, int8PtrTy, int32Ty);

          const char * trace_func;
          int param_pos;


          if( map_custom_receive.count(called_func->getName().data()) ) {

            trace_func = "trace_receive";

            auto it = map_custom_receive.find(called_func->getName().data());
            param_pos = it->second;

          } else {

            trace_func = "trace_send";

            auto it = map_custom_send.find(called_func->getName().data());
            param_pos = it->second;
          }

          auto helper = M.getOrInsertFunction(trace_func, helperTy);


          Value * buf_operand;
          Value * buf_size;
          int struct_size;

          if(param_pos != -1) {

			auto arg = called_func->arg_begin();
			int arg_no = 0;

			while(arg != called_func->arg_end() && arg_no < param_pos) {
			  arg++;
			  arg_no++;
			}


            Type * T = arg->getType();


            if( T->isPointerTy() ) {
              if( T->getContainedType(0)->isStructTy() ) {

                Type * PT = T->getContainedType(0);
                llvm::DataLayout* dl = new llvm::DataLayout(&M);
                struct_size = dl->getTypeAllocSize(PT); 

                //WARNF("Type %s size: %d\n", PT->getStructName().data(), struct_size);

                buf_operand = call_instr->getOperand(param_pos);
                buf_size = llvm::ConstantInt::get(int32Ty, struct_size, true);

              } else {
                //T->getContainedType(0)->isIntegerTy(8) || T->getContainedType(0)->isVoidTy()

                WARNF("Non-struct pointer types (char*, void*) at custom function %s at position %d not yet supported (PASSING NULL, size = 0)\n", called_func->getName().data(), param_pos);

                buf_operand = ConstantPointerNull::get( PointerType::get(voidTy, 0));
                buf_size = llvm::ConstantInt::get(int32Ty, 0, true);
              }
            }
            else {
              WARNF("No pointer type found for custom function %s at position %d (PASSING NULL, size = 0)\n", called_func->getName().data(), param_pos);

              buf_operand = ConstantPointerNull::get( PointerType::get(voidTy, 0));
              buf_size = llvm::ConstantInt::get(int32Ty, 0, true);
            }


          } else {

            WARNF("NO BUFFER POINTER PROVIDED FOR CUSTOM FUNCTION %s (PASSING NULL, size = 0)\n", called_func->getName().data());
            buf_operand = ConstantPointerNull::get( PointerType::get(voidTy, 0));
            buf_size = llvm::ConstantInt::get(int32Ty, 0, true);
          }


          IRBuilder<> builder(call_instr);
          builder.CreateCall(helper, {buf_operand, buf_size});

        }
        else if( called_func->getName() == "read" ) {
          OKF("Found function call: %s\n", called_func->getName().data());

          auto * voidTy = Type::getVoidTy(M.getContext());
          auto * int32Ty = Type::getInt32Ty(M.getContext());
          auto * int8PtrTy = Type::getInt8PtrTy(M.getContext()); /* pass buffer address */

          auto * helperTy = FunctionType::get(voidTy, {int32Ty, int8PtrTy, int32Ty}, false);
          auto helper_read = M.getOrInsertFunction("trace_read", helperTy);

          /* Note: Operand 2 (size_t) is 64 bit wide */
          std::vector<Value *> call_args = {call_instr->getOperand(0), call_instr->getOperand(1), call_instr->getOperand(2)};
          
          IRBuilder<> builder(call_instr);
          builder.CreateCall(helper_read, call_args);

        }
        else if( called_func->getName() == "write" ) {
          OKF("Found function call: %s\n", called_func->getName().data());

          auto * voidTy = Type::getVoidTy(M.getContext());
          auto * int32Ty = Type::getInt32Ty(M.getContext());
          auto * int8PtrTy = Type::getInt8PtrTy(M.getContext()); /* pass buffer address */

          auto * helperTy = FunctionType::get(voidTy, {int32Ty, int8PtrTy, int32Ty}, false);
          auto helper_write = M.getOrInsertFunction("trace_write", helperTy);

          std::vector<Value *> call_args = {call_instr->getOperand(0), call_instr->getOperand(1), call_instr->getOperand(2)};

          IRBuilder<> builder(call_instr);
          builder.CreateCall(helper_write, call_args);

        }
        else if( called_func->getName() == "fprintf" ) {
          OKF("Found function call: %s\n", called_func->getName().data());

          auto * voidTy = Type::getVoidTy(M.getContext());
          auto * int8PtrTy = Type::getInt8PtrTy(M.getContext());
          auto * int32Ty = Type::getInt32Ty(M.getContext()); /* pass buffer size */

          auto * helperTy = FunctionType::get(voidTy, { int8PtrTy, int8PtrTy, int32Ty }, false);
          auto helper = M.getOrInsertFunction("trace_fprintf", helperTy);

          std::vector<Value *> call_args = {call_instr->getOperand(0), call_instr->getOperand(1), call_instr};

          IRBuilder<> builder(call_instr);
          builder.SetInsertPoint(call_instr->getNextNode());
          builder.CreateCall(helper, call_args);

        }
        else if( called_func->getName() == "fgets" ) {
          OKF("Found function call: %s\n", called_func->getName().data());

          auto * voidTy = Type::getVoidTy(M.getContext());
          auto * int8PtrTy = Type::getInt8PtrTy(M.getContext());
          auto * int32Ty = Type::getInt32Ty(M.getContext()); /* pass buffer size */

          auto * helperTy = FunctionType::get(voidTy, { int8PtrTy, int8PtrTy, int32Ty }, false);
          auto helper = M.getOrInsertFunction("trace_fgets", helperTy);

          std::vector<Value *> call_args = {call_instr->getOperand(2), call_instr->getOperand(0), call_instr->getOperand(1)};

          IRBuilder<> builder(call_instr);
          //builder.SetInsertPoint(call_instr->getNextNode());
          builder.CreateCall(helper, call_args);

        }
        else if( called_func->getName() == "fwrite" ) {
          OKF("Found function call: %s\n", called_func->getName().data());

          auto * voidTy = Type::getVoidTy(M.getContext());
          auto * int8PtrTy = Type::getInt8PtrTy(M.getContext());
          auto * int32Ty = Type::getInt32Ty(M.getContext()); /* pass buffer size */

          auto * helperTy = FunctionType::get(voidTy, { int8PtrTy, int8PtrTy, int32Ty, int32Ty }, false);
          auto helper = M.getOrInsertFunction("trace_fwrite", helperTy);

          std::vector<Value *> call_args = {call_instr->getOperand(3), call_instr->getOperand(0), call_instr->getOperand(1), call_instr->getOperand(2)};

          IRBuilder<> builder(call_instr);
          //builder.SetInsertPoint(call_instr->getNextNode());
          builder.CreateCall(helper, call_args);

        }
        else if( called_func->getName() == "fread" ) {
          OKF("Found function call: %s\n", called_func->getName().data());

          auto * voidTy = Type::getVoidTy(M.getContext());
          auto * int8PtrTy = Type::getInt8PtrTy(M.getContext());
          auto * int32Ty = Type::getInt32Ty(M.getContext()); /* pass buffer size */

          auto * helperTy = FunctionType::get(voidTy, { int8PtrTy, int8PtrTy, int32Ty, int32Ty }, false);
          auto helper = M.getOrInsertFunction("trace_fread", helperTy);

          std::vector<Value *> call_args = {call_instr->getOperand(3), call_instr->getOperand(0), call_instr->getOperand(1), call_instr->getOperand(2)};

          IRBuilder<> builder(call_instr);
          //builder.SetInsertPoint(call_instr->getNextNode());
          builder.CreateCall(helper, call_args);

        }
        else if( called_func->getName() == "_exit" ) {
          OKF("Found function call: %s\n", called_func->getName().data());

          auto * voidTy = Type::getVoidTy(M.getContext());

          auto * helperTy = FunctionType::get(voidTy, voidTy);
          auto helper = M.getOrInsertFunction("end_state_tracer", helperTy);

          IRBuilder<> builder(call_instr);
          builder.CreateCall(helper, {});

        }
        else if( called_func->getName() == "close" ) {
          OKF("Found function call: %s\n", called_func->getName().data());

          auto * voidTy = Type::getVoidTy(M.getContext());
          auto * int32Ty = Type::getInt32Ty(M.getContext());

          auto * helperTy = FunctionType::get(voidTy, int32Ty);
          auto helper_read = M.getOrInsertFunction("trace_close", helperTy);

          IRBuilder<> builder(call_instr);
          builder.SetInsertPoint(call_instr->getNextNode());
          builder.CreateCall(helper_read, {call_instr->getOperand(0)});

        }
        else if( called_func->getName() == "fclose" ) {
          OKF("Found function call: %s\n", called_func->getName().data());

          auto * voidTy = Type::getVoidTy(M.getContext());
          auto * int8PtrTy = Type::getInt8PtrTy(M.getContext());

          auto * helperTy = FunctionType::get(voidTy, int8PtrTy);
          auto helper = M.getOrInsertFunction("trace_fclose", helperTy);

          IRBuilder<> builder(call_instr);
          builder.SetInsertPoint(call_instr->getNextNode());
          builder.CreateCall(helper, {call_instr->getOperand(0)});

        }


      }

    }

    for (SmallVectorImpl<CallInst*>::iterator it=stack_lookups.begin(), 
          e=stack_lookups.end() ; e!=it ; it++) {

      CallInst * call_instr = *it;
      auto called_func = call_instr->getCalledFunction();

      auto * voidTy = Type::getVoidTy(M.getContext());
      auto * int8PtrTy = Type::getInt8PtrTy(M.getContext());
      auto * int64Ty = Type::getInt64Ty(M.getContext());


      auto * helperTy = FunctionType::get(voidTy, int8PtrTy, int64Ty);

      IRBuilder<> builder(call_instr);

      // test if allocated stack size is greater or equal than threshold
      auto stack_size_cmp = builder.CreateICmpUGE(call_instr->getOperand(0), ConstantInt::get(int64Ty, MIN_STACK_ALLOC_SIZE));
      auto split_before = SplitBlockAndInsertIfThen(stack_size_cmp, call_instr, false);
      builder.SetInsertPoint(split_before);

      if( called_func->getName().find("start") != StringRef::npos ) {

        auto helper_malloc = M.getOrInsertFunction("new_stack_alloc_record", helperTy);
        builder.CreateCall(helper_malloc, {call_instr->getOperand(1), call_instr->getOperand(0)});

      } else {

        auto helper_malloc = M.getOrInsertFunction("free_stack_alloc_record", helperTy);
        builder.CreateCall(helper_malloc, {call_instr->getOperand(1), call_instr->getOperand(0)});
      }

    }
  }

  /* Say something nice. */

  if (!be_quiet) {

    if (!inst_blocks) WARNF("No instrumentation targets found.");
    else OKF("Instrumented %u locations (%s mode, ratio %u%%).",
             inst_blocks, getenv("AFL_HARDEN") ? "hardened" :
             ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN")) ?
              "ASAN/MSAN" : "non-hardened"), inst_ratio);

  }

  return true;

}


static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  PM.add(new AFLCoverage());

}


static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_ModuleOptimizerEarly, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);
