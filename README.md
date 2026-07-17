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
