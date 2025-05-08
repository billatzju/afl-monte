based on afl++, i am trying to develop a new fuzzer. 

afl++ fuzzer has the trace bits which record the hit counts of each transition between blocks. I instead use the transition between blocks as the state representation, and initially assign each state a score and update the state score during each execution.
I try to prioritize these states that can has more potential to reach those states with higher scores.
For each execution, the execution score is defined as its outcome, i.e, new state reached, new hit counts and etc.. 
For each state transition reached in the execution, the closer it is to the end of the execution, we add a higher score to the state's score. However, if nothing happens on the execution, the score of each reached state also decays- the closer the state is to the end of the execution, we reduce the score with a greater amount.

When it comes 
two options

april 24,
pass a pointer of a double to save_if_interesting to store the execution score, and use the score to update the heap if it the new input is saved.

during the first run of the seed, the default score is going to be set as -0.1. It is used to decay the score of the state if nothing happens upon reaching such state. The seed is first run as input generated via seeds mutation,
and the score was already added. That's why we will need to decay the score we run the program with this seed.

