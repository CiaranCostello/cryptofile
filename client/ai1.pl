%goal node is any node that is a multiple of the target
goal(N,Target) :- 0 is N mod Target.

%eg N=1 and seed=2
%M=2 and cost=1 or M=3 and cost=2
arc([N,NCost],[M,MCost],Seed) :- M is N*Seed, MCost is NCost+1.
arc([N,NCost],[M,MCost],Seed) :- M is N*Seed + 1, MCost is NCost+2.

%heuristic value of N given target
h(N,Hvalue,Target) :- goal(N,Target), !, Hvalue is 0
;
Hvalue is 1/N.

%get least cost 
less_than([Node1,Cost1],[Node2,Cost2],Target) :-
h(Node1,Hvalue1,Target), h(Node2,Hvalue2,Target),
F1 is Cost1+Hvalue1, F2 is Cost2+Hvalue2,
F1 =< F2.

%insert element into a list based on the heuristic value
insert(E, [], [E], _).
insert(E, [H|T], [E,H|T], Target) :- less_than(E, H, Target), !.
insert(E, [H|T], [H|Combined], Target) :- insert(E, T, Combined, Target).

%Dependancies of A*.
%setof is a built in predicate
%combines the two lists and sorts it based on heuristic value
add2frontier(FNode, [], FNode, _).
add2frontier([],FRest,FRest, _).
add2frontier([H|T],FRest, New, Target) :- insert(H, FRest, NewRest, Target), add2frontier(T, NewRest, New, Target).

%search function
search([[Node,_]|_], _, Target, Node) :- goal(Node, Target).
search([[Node,Cost]|FRest], Seed, Target, Found) :- setof(X,arc([Node,Cost],X,Seed), FNode),
													add2frontier(FNode,FRest,FNew, Target),
													search(FNew, Seed, Target, Found).

%define A* predicate 
astar(Start,Seed,Target,Found) :- search([[Start, 0]], Seed, Target, Found).