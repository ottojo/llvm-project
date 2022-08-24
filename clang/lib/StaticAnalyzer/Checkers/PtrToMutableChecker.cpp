#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "llvm/Support/Debug.h"
#include <iostream>
#define DEBUG_TYPE "PtrToMutableChecker"

#include "clang/AST/Attr.h"

using namespace clang;
using namespace ento;
using namespace llvm;

struct SmartPtrConstness {
  enum Kind { Const, Mutable } K;
  SmartPtrConstness(Kind InK) : K(InK) {}
  bool operator==(const SmartPtrConstness &rhs) const { return K == rhs.K; }
  void Profile(llvm::FoldingSetNodeID &ID) const { ID.AddInteger(K); }
  bool isMutable() const { return K == Kind::Mutable; }
  static SmartPtrConstness getMutable() { return SmartPtrConstness(Mutable); }
  static SmartPtrConstness getConst() { return SmartPtrConstness(Const); }
};

REGISTER_MAP_WITH_PROGRAMSTATE(SmartPtrConstnessMap, const MemRegion *,
                               SmartPtrConstness)

class PtrToMutableChecker : public Checker<check::PostCall, check::PreCall> {
public:
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    if (!Call.getCalleeIdentifier()) {
      return;
    }
    if (Call.getCalleeIdentifier()->getName() != "make_shared") {
      // TODO: Find make_shared somewhat like Call.isGlobalCFunction()?
      return;
    }

    std::cout << "Found a make_shared call, tagging...\n";

    const auto *Pointer = Call.getReturnValue().getAsRegion();
    if (!Pointer) {
      std::cout << "getAsRegion = 0?\n";
      return;
    }

    std::cout << "Symbol at " << Pointer << "\n";

    ProgramStateRef State = C.getState();

    const auto *decl = Call.getDecl();
    if (!decl) {
      return;
    }

    auto templateType = decl->getAsFunction()
                            ->getTemplateSpecializationArgs()
                            ->get(0)
                            .getAsType();

    if (templateType.isConstQualified()) {
      State = State->set<SmartPtrConstnessMap>(Pointer,
                                               SmartPtrConstness::getConst());
    } else {
      State = State->set<SmartPtrConstnessMap>(Pointer,
                                               SmartPtrConstness::getMutable());
    }
    C.addTransition(State);
  }

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    // If parameter has attribute and value is not tagged, error!

    const auto *CallDecl = Call.getDecl();
    if (!CallDecl) {
      return;
    }

    const auto *FunctionDecl = CallDecl->getAsFunction();
    if (!FunctionDecl) {
      return;
    }

    std::vector<unsigned int> relevant_parameters{};
    for (unsigned int i = 0; i < FunctionDecl->param_size(); i++) {
      if (FunctionDecl->parameters()[i]->hasAttr<PtrToMutableAttr>()) {
        std::cout << "Found parameter with ptr_to_mutable attribute at index "
                  << i << "\n";
        relevant_parameters.push_back(i);
      }
    }

    for (unsigned int i = 0; i < Call.getNumArgs(); i++) {
      // if(!relevant_parameters.contains(i)){
      if (std::find(relevant_parameters.begin(), relevant_parameters.end(),
                    i) == relevant_parameters.end()) {
        // std::cout << "...is not interesting\n";
        continue;
      }
      std::cout << "Checking function parameter at index " << i
                << "...is interesting!\n";

      const auto *PtrSymbol = Call.getArgSVal(i).getAsRegion();
      if (!PtrSymbol) {
        std::cout << "Not a symbol(?)\n";
        return;
      }
      const SmartPtrConstness *Constness =
          C.getState()->get<SmartPtrConstnessMap>(PtrSymbol);
      if (!Constness) {
        std::cout << "Constness not tagged\n";
        continue;
      }
      if (!Constness->isMutable()) {
        std::cout << "Found bug, emitting error!\n";
        ExplodedNode *ErrNode = C.generateErrorNode();
        if (!ErrNode) {
          return;
        }

        auto R = std::make_unique<PathSensitiveBugReport>(
            BugType(this, "Non-Mut", ""), "Using non-mutable ptr", ErrNode);
        R->addRange(Call.getSourceRange());
        C.emitReport(std::move(R));
      } else {
        std::cout << "Argument is mutable\n";
      }
    }
  }
};

void ento::registerPtrToMutableChecker(CheckerManager &mgr) {
  mgr.registerChecker<PtrToMutableChecker>();
}

bool ento::shouldRegisterPtrToMutableChecker(const CheckerManager &mgr) {
  return true;
}
