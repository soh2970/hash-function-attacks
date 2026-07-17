# Hash Function Attacks

## Overview
This project explores practical attacks against weakened cryptographic hash functions by implementing multiple collision-finding algorithms in Python.
The implementations demonstrate both time efficient and memory efficient approaches to discovering hash collisions while illustrating the security principles behind collision resistance and the birthday paradox.


## Implemented Algorithms
### Birthday Attack
Implemented a birthday attack against a truncated SHA-256 hash function by generating large numbers of candidate inputs and detecting collisions using a hash table.

### Useful Collision Generation
Generated semantically different messages that produce identical hash values by creating millions of message variations while preserving their intended meanings.

### Floyd's Cycle Detection
Implemented Floyd's tortoise and hare algorithm to discover collisions using constant memory, demonstrating the tradeoff between execution time and memory usage.

### Useful Collisions with Constant Memory
Extended Floyd's algorithm to generate meaningful hash collisions through an injective message mapping, combining collision attacks with semantic message generation.


## Skills Demonstrated
- Python
- Cryptography
- Hash Functions
- SHA-256
- Birthday Attack
- Floyd's Cycle Detection
- Collision Resistance
- Algorithm Design
- Time Memory Tradeoffs


## Technologies
- Python 3
- SHA-256
- Cryptographic Hash Functions
- Dictionaries
- Graph Traversal
- Cycle Detection

## Results
The implemented algorithms were evaluated using a truncated 40-bit SHA-256 hash function. The observed performance closely matched the theoretical expectations for collision-finding algorithms.

| Problem | Algorithm | Experimental Result | Expected Behavior |
|---------|-----------|--------------------:|------------------|
| 1 | Birthday Attack | ~1,289,670 hash evaluations | ≈ 2²⁰ (1,048,576) evaluations |
| 2 | Useful Collision Generation | Collision after ~3,173,718 evaluations | Collision expected after searching millions of message variants |
| 3 | Floyd's Cycle Detection | ~4,313,362 hash evaluations | Approximately 3–5× the birthday bound using O(1) memory |
| 4 | Useful Collision (Floyd's) | Useful collision found after 4 attempts (~9,851,162 evaluations) | Expected average of ~2 attempts due to 50% probability of semantic collision |

The results demonstrate the practical tradeoff between memory usage and execution time. While the birthday attack finds collisions more quickly using a hash table, Floyd's cycle detection significantly reduces memory consumption at the cost of additional hash evaluations.

## Key Findings
- Successfully implemented four collision-finding algorithms in Python.
- Experimental results closely matched the theoretical birthday bound.
- Demonstrated the time-memory tradeoff between hash table based and constant memory collision attacks.
- Generated meaningful hash collisions while preserving different message semantics.

## Project Structure
```
hash-function-attacks/
│
├── proj2.py
├── README.md
└── LICENSE
```


## Learning Outcomes
This project provided practical experience implementing collision attacks against weakened hash functions while exploring the computational tradeoffs between memory usage and execution time. It reinforced key concepts including collision resistance, the birthday paradox, cycle detection algorithms, and secure hash function design.


## Disclaimer
This project was developed for educational purposes to study cryptographic hash functions and known collision-finding techniques.
