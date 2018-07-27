//===- FuzzerTracePC.h - Internal header for the Fuzzer ---------*- C++ -* ===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// fuzzer::TracePC
//===----------------------------------------------------------------------===//

#ifndef LLVM_FUZZER_TRACE_PC
#define LLVM_FUZZER_TRACE_PC

#include "FuzzerDefs.h"
#include "FuzzerDictionary.h"
#include "FuzzerValueBitMap.h"

#include <set>
#include <map>
#include <string>
#include <fstream>
namespace fuzzer {
// TableOfRecentCompares (TORC) remembers the most recently performed
// comparisons of type T.
// We record the arguments of CMP instructions in this table unconditionally
// because it seems cheaper this way than to compute some expensive
// conditions inside __sanitizer_cov_trace_cmp*.
// After the unit has been executed we may decide to use the contents of
// this table to populate a Dictionary.
template<class T, size_t kSizeT>
struct TableOfRecentCompares {
  static const size_t kSize = kSizeT;
  struct Pair {
    T A, B;
  };
  ATTRIBUTE_NO_SANITIZE_ALL
  void Insert(size_t Idx, const T &Arg1, const T &Arg2) {
    Idx = Idx % kSize;
    Table[Idx].A = Arg1;
    Table[Idx].B = Arg2;
  }

  Pair Get(size_t I) { return Table[I % kSize]; }

  Pair Table[kSize];
};

template <size_t kSizeT>
struct MemMemTable {
  static const size_t kSize = kSizeT;
  Word MemMemWords[kSize];
  Word EmptyWord;

  void Add(const uint8_t *Data, size_t Size) {
    if (Size <= 2) return;
    Size = std::min(Size, Word::GetMaxSize());
    size_t Idx = SimpleFastHash(Data, Size) % kSize;
    MemMemWords[Idx].Set(Data, Size);
  }
  const Word &Get(size_t Idx) {
    for (size_t i = 0; i < kSize; i++) {
      const Word &W = MemMemWords[(Idx + i) % kSize];
      if (W.size()) return W;
    }
    EmptyWord.Set(nullptr, 0);
    return EmptyWord;
  }
};

// Chairtha : use to parse in the prediction
//class PredictionParser{
//public:
    //uint8_t getCount(int idx) { 
        //auto II = EdgeCounts.find(idx);
        //if(II != EdgeCounts.end()) return II->second;
        //return 0; // might be a problem
    //}

    //void Parse(const char * filename){
        //EdgeCounts.clear();
        //std::ifstream infile(filename);
        //int edge, count;
        //while(infile >> edge >> count){
            //EdgeCounts[edge] = (uint8_t)count;

        //}
        //DumpPrediction();
    //}

    //void DumpPrediction() {
        //for(auto II : EdgeCounts) 
            //Printf("Edge : %d Count : %d\n", II.first, II.second);
    //}

    //void ComputeDiffs(){
        //for(auto II : EdgeCounts){
            //int edge = II.first;
            //uint8_t prediction = II.second;
            
            //DiffCounters[edge] = prediction > DiffCounters[edge] ? prediction-DiffCounters[edge] : DiffCounters[edge] - prediction ;
            //Printf("Actual Count : %d\n", DiffCounters[edge]);
            //Printf("Predicted count : %d\n", prediction);
            //Printf("Edge : %d Diff : %d\n", edge, DiffCounters[edge]);
        //}
    //}

    //uint8_t* GetDiffCounters() { return DiffCounters;}
    //void ClearCounters() { 
        //for(int i=0; i < diffCounterSize; i++) DiffCounters[i] = 0;
    //}
    
     //this computes how close the current input is to the prediction
     //TODO : Is Euclidean distance the correct meassure?
    //int ComputeDistance() {
        //int dist = 0;
        //for (int i=0; i < diffCounterSize; i++) dist += DiffCounters[i]*DiffCounters[i];

        //return dist;
    //}

    
//private:
    //static const size_t diffCounterSize = 1 << 21;
    //std::map<int, uint8_t> EdgeCounts;
    //uint8_t DiffCounters[diffCounterSize];
//};



class TracePC {

 public:
  static const size_t kNumPCs = 1 << 21;
  // How many bits of PC are used from __sanitizer_cov_trace_pc.
  static const size_t kTracePcBits = 18;

  void HandleInit(uint32_t *Start, uint32_t *Stop);
  void HandleInline8bitCountersInit(uint8_t *Start, uint8_t *Stop);
  void HandlePCsInit(const uintptr_t *Start, const uintptr_t *Stop);
  void HandleCallerCallee(uintptr_t Caller, uintptr_t Callee);
  template <class T> void HandleCmp(uintptr_t PC, T Arg1, T Arg2);
  size_t GetTotalPCCoverage();
  void SetUseCounters(bool UC) { UseCounters = UC; }
  void SetUseClangCoverage(bool UCC) { UseClangCoverage = UCC; }
  void SetUseValueProfile(bool VP) { UseValueProfile = VP; }
  void SetPrintNewPCs(bool P) { DoPrintNewPCs = P; }
  void SetPrintNewFuncs(size_t P) { NumPrintNewFuncs = P; }
  void UpdateObservedPCs();
  template <class Callback> void CollectFeatures(Callback CB) const ;

  void ResetMaps() {
    ValueProfileMap.Reset();
    if (NumModules)
      memset(Counters(), 0, GetNumPCs());
    ClearExtraCounters();
    ClearInlineCounters();
    if (UseClangCoverage)
      ClearClangCounters();
    // Charitha
    if(PredMode)
      Clear32BitCounters();
  }

  void ClearInlineCounters();

  void UpdateFeatureSet(size_t CurrentElementIdx, size_t CurrentElementSize);
  void PrintFeatureSet();

  void PrintModuleInfo();

  void PrintCoverage();
  void DumpCoverage();

  void AddValueForMemcmp(void *caller_pc, const void *s1, const void *s2,
                         size_t n, bool StopAtZero);

  TableOfRecentCompares<uint32_t, 32> TORC4;
  TableOfRecentCompares<uint64_t, 32> TORC8;
  TableOfRecentCompares<Word, 32> TORCW;
  MemMemTable<1024> MMT;

  size_t GetNumPCs() const {
    return NumGuards == 0 ? (1 << kTracePcBits) : Min(kNumPCs, NumGuards + 1);
  }
  uintptr_t GetPC(size_t Idx) {
    assert(Idx < GetNumPCs());
    return PCs()[Idx];
  }

  void RecordInitialStack();
  uintptr_t GetMaxStackOffset() const;

  template<class CallBack>
  void ForEachObservedPC(CallBack CB) {
    for (auto PC : ObservedPCs)
      CB(PC);
  }

  // charitha TODO : this memcpy can be dangerous
  //void SetPredictor(PredictionParser * pf) { PF = pf;}
  void ParsePredFile(const char* filename);
  uint32_t* GetDiffCounters() const;

  void ClearDiffCounters();
  void Clear32BitCounters();
  void DumpPrediction();
  void ComputeDiffs();
  unsigned ComputeDistance();
private:

  //PredictionParser * PF = 0;
  bool PredMode = false;
  std::map<unsigned, uint32_t> PredEdgeCounts;  // map to store the predicted edge counts
  //uint32_t DiffCounters[fuzzer::TracePC::kNumPCs];

  bool UseCounters = false;
  bool UseValueProfile = false;
  bool UseClangCoverage = false;
  bool DoPrintNewPCs = false;
  size_t NumPrintNewFuncs = 0;

  struct Module {
    uint32_t *Start, *Stop;
  };

  Module Modules[4096];
  size_t NumModules;  // linker-initialized.
  size_t NumGuards;  // linker-initialized.

  struct { uint8_t *Start, *Stop; } ModuleCounters[4096];
  size_t NumModulesWithInline8bitCounters;  // linker-initialized.
  size_t NumInline8bitCounters;

  struct PCTableEntry {
    uintptr_t PC, PCFlags;
  };

  struct { const PCTableEntry *Start, *Stop; } ModulePCTable[4096];
  size_t NumPCTables;
  size_t NumPCsInPCTables;

  uint8_t *Counters() const;
  uint32_t *Counters32Bit() const;
  uintptr_t *PCs() const;

  Set<uintptr_t> ObservedPCs;
  Set<uintptr_t> ObservedFuncs;

  ValueBitMap ValueProfileMap;
  uintptr_t InitialStack;

};

class UniqueEdges {
public :
    // Charitha 
    std::set<std::pair<int, int>> UniqueEdgeCounts;

    // Charitha
    void AddUniqueEdge(int edge, int count){
      UniqueEdgeCounts.insert(std::pair<int, int>(edge, count));
    }
    void DumpUniqueEdges(){
      Printf("EDGES touched so far : \n");
      for(auto II : UniqueEdgeCounts)
          Printf("EDGE ID : %d\t Count : %d\n", II.first, II.second);
    }
};


template <class Callback>
// void Callback(size_t FirstFeature, size_t Idx, uint8_t Value);
ATTRIBUTE_NO_SANITIZE_ALL
void ForEachNonZeroByte(const uint8_t *Begin, const uint8_t *End,
                        size_t FirstFeature, Callback Handle8bitCounter) {
  typedef uintptr_t LargeType;
  const size_t Step = sizeof(LargeType) / sizeof(uint8_t);
  const size_t StepMask = Step - 1;
  auto P = Begin;
  // Iterate by 1 byte until either the alignment boundary or the end.
  for (; reinterpret_cast<uintptr_t>(P) & StepMask && P < End; P++)
    if (uint8_t V = *P){
      //Printf(" E:%d C:%d\n", P-Begin, V);
      Handle8bitCounter(FirstFeature, P - Begin, V);
    }

  // Iterate by Step bytes at a time.
  for (; P < End; P += Step)
    if (LargeType Bundle = *reinterpret_cast<const LargeType *>(P))
      for (size_t I = 0; I < Step; I++, Bundle >>= 8)
        if (uint8_t V = Bundle & 0xff){
          //Printf(" E:%d C:%d\n", P-Begin+I, V);
          Handle8bitCounter(FirstFeature, P - Begin + I, V);
        }

  // Iterate by 1 byte until the end.
  for (; P < End; P++)
    if (uint8_t V = *P){
      //Printf(" E:%d C:%d\n", P-Begin, V);
      Handle8bitCounter(FirstFeature, P - Begin, V);
    }

}

// Charitha : this is a minimal implementation without 
// considering the speed
template <class Callback>
// void Callback(size_t FirstFeature, size_t Idx, uint8_t Value);
ATTRIBUTE_NO_SANITIZE_ALL
void ForEachNonZeroFourByte(const uint32_t *Begin,
                        size_t FirstFeature, Callback Handle8bitCounter,
                        const std::map<unsigned,uint32_t> EdgeMap) {
    for(auto II : EdgeMap){
        //Printf("DIFF E:%d D:%d\n", II.first, *(Begin + II.first));
        uint32_t V = *(Begin+II.first);
        Handle8bitCounter(FirstFeature, II.first, (uint8_t)V);
    }
}


// Given a non-zero Counter returns a number in the range [0,7].
template<class T>
unsigned CounterToFeature(T Counter) {
    // Returns a feature number by placing Counters into buckets as illustrated
    // below.
    //
    // Counter bucket: [1] [2] [3] [4-7] [8-15] [16-31] [32-127] [128+]
    // Feature number:  0   1   2    3     4       5       6       7
    //
    // This is a heuristic taken from AFL (see
    // http://lcamtuf.coredump.cx/afl/technical_details.txt).
    //
    // This implementation may change in the future so clients should
    // not rely on it.
    assert(Counter);
    unsigned Bit = 0;
    /**/ if (Counter >= 128) Bit = 7;
    else if (Counter >= 32) Bit = 6;
    else if (Counter >= 16) Bit = 5;
    else if (Counter >= 8) Bit = 4;
    else if (Counter >= 4) Bit = 3;
    else if (Counter >= 3) Bit = 2;
    else if (Counter >= 2) Bit = 1;
    return Bit;
}

template<class T>
unsigned DiffCounterToFeature(T Counter) {
    unsigned Bit = 0;
    /**/ if (Counter >= 128) Bit = 7;
    else if (Counter >= 32) Bit = 6;
    else if (Counter >= 16) Bit = 5;
    else if (Counter >= 8) Bit = 4;
    else if (Counter >= 4) Bit = 3;
    else if (Counter >= 3) Bit = 2;
    else if (Counter >= 2) Bit = 1;
    return Bit;
}

template <class Callback>  // void Callback(size_t Feature)
ATTRIBUTE_NO_SANITIZE_ADDRESS
__attribute__((noinline))
void TracePC::CollectFeatures(Callback HandleFeature) const {
  uint8_t *Counters = this->Counters();
  size_t N = GetNumPCs();
  auto Handle8bitCounter = [&](size_t FirstFeature,
                               size_t Idx, uint8_t Counter) {
    if (UseCounters)
      HandleFeature(FirstFeature + Idx * 8 + CounterToFeature(Counter));
    else
      HandleFeature(FirstFeature + Idx);
  };
  auto Handle8bitDiffCounter = [&](size_t FirstFeature,
                               size_t Idx, uint8_t Counter) {
    unsigned bit = DiffCounterToFeature(Counter);
    //Printf("Bit = %d\n", bit);
    for(int i=bit; i<=7; i++){
        HandleFeature(FirstFeature + Idx * 8 + i);
    }
  };


  size_t FirstFeature = 0;
    
  // Charitha : For now assume there are not inline bit counters
  // Use a map to store indexes of non zero edges
  if (!NumInline8bitCounters) {
    ForEachNonZeroByte(Counters, Counters + N, FirstFeature, Handle8bitCounter);
    FirstFeature += N * 8;
  }

  // Charitha : experimental , for each edge take the diff from a target count
  // and use that as a feature
  if(PredMode){
      ForEachNonZeroFourByte(GetDiffCounters(), FirstFeature, Handle8bitDiffCounter, PredEdgeCounts);
      FirstFeature += N*8;
  }

  if (NumInline8bitCounters) {
    assert(false && "Inline 8bit counters are not handled");
    for (size_t i = 0; i < NumModulesWithInline8bitCounters; i++) {
      ForEachNonZeroByte(ModuleCounters[i].Start, ModuleCounters[i].Stop,
                         FirstFeature, Handle8bitCounter);
      FirstFeature += 8 * (ModuleCounters[i].Stop - ModuleCounters[i].Start);
    }
  }

  if (size_t NumClangCounters = ClangCountersEnd() - ClangCountersBegin()) {
      
    assert(false && "Clang counters are not handled");
    auto P = ClangCountersBegin();
    for (size_t Idx = 0; Idx < NumClangCounters; Idx++)
      if (auto Cnt = P[Idx]) {
        if (UseCounters)
          HandleFeature(FirstFeature + Idx * 8 + CounterToFeature(Cnt));
        else
          HandleFeature(FirstFeature + Idx);
      }
    FirstFeature += NumClangCounters;
  }

  ForEachNonZeroByte(ExtraCountersBegin(), ExtraCountersEnd(), FirstFeature,
                     Handle8bitCounter);
  FirstFeature += (ExtraCountersEnd() - ExtraCountersBegin()) * 8;

  if (UseValueProfile) {
    ValueProfileMap.ForEach([&](size_t Idx) {
      HandleFeature(FirstFeature + Idx);
    });
    FirstFeature += ValueProfileMap.SizeInBits();
  }

  // Step function, grows similar to 8 * Log_2(A).
  auto StackDepthStepFunction = [](uint32_t A) -> uint32_t {
    if (!A) return A;
    uint32_t Log2 = Log(A);
    if (Log2 < 3) return A;
    Log2 -= 3;
    return (Log2 + 1) * 8 + ((A >> Log2) & 7);
  };
  assert(StackDepthStepFunction(1024) == 64);
  assert(StackDepthStepFunction(1024 * 4) == 80);
  assert(StackDepthStepFunction(1024 * 1024) == 144);

  // Charitha : need to profile stack depth for this branch to take.
  if (auto MaxStackOffset = GetMaxStackOffset())
    HandleFeature(FirstFeature + StackDepthStepFunction(MaxStackOffset / 8));


}

extern TracePC TPC;
//extern PredictionParser PredFile;
}  // namespace fuzzer

#endif  // LLVM_FUZZER_TRACE_PC
