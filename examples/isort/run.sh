/var/scratch/cgusthin/llvm-latest/build/bin/clang++ -g -std=c++11 -fsanitize=address -fsanitize-coverage=trace-pc-guard \
-L/opt/gcc/7.1.0/lib64/ \
isort_driver.cc ../../libFuzzer.a \
-o target
./target   -use_feature_frequency=1 -max_total_time=3600  -pred_mode=1 -exec_corpus_only=0 -use_small_scale=1 -max_len=100 ./corpus
#echo "TOOL X" | mailx -s "job finished" cgusthin@ecn.purdue.edu
