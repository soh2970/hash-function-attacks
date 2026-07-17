from Crypto.Hash import SHA256
import struct
import itertools

################################################################################
# Hash Function
################################################################################

# x should be a bytes/bytearray.
# This returns "binary" data (i.e. unprintable bytes).
def proj2hash(x):
    h = SHA256.new()
    h.update(x)
    return h.digest()[:5]

################################################################################
# Problem 1 SOLUTION
################################################################################

def _birthday_trial(pre):
    #Find a collision among strings that start with `pre`. Returns the number of proj2hash evaluations performed.
    seen = {} #digest -> counter value that produced it
    counter = 0
    while True:
        #Append a 4 byte little endian counter so strings stay short but unique
        msg = pre + struct.pack('<I', counter)
        digest = proj2hash(msg)
        if digest in seen:
            #Collision found between counter values seen[digest] and counter
            return counter + 1 #total evaluations (0 to indexed, so +1)
        seen[digest] = counter
        counter += 1
 
 
def problem1(id):
    #Run 10 birthday attack trials (one per ASCII digit '0'to '9' prepended to id), count proj2hash evaluations per trial, and return the average count.
    total_evals = 0
    for digit in b'0123456789': #iterate over the 10 digit byte values
        pre = bytes([digit]) + id #prepend digit to id
        evals = _birthday_trial(pre)
        total_evals += evals
 
    average = total_evals / 10
    print(f"[Problem 1] Average evaluations over 10 trials: {average:.1f}")
    print(f"[Problem 1] Expected (birthday bound 2^20): {2**20}")
    return average


################################################################################
# Problem 2 SOLUTION
################################################################################

def problem2(id):
    id_str = id.decode() if isinstance(id, bytes) else id
 
    prefixes = [b'', b'Note: ', b'Reminder: ', b'FYI: ']
    names = [b'Alex', b'ALEX', b'alex']
    verbs = [b'owes', b'owes you', b'currently owes']
    s_opts = [b' ', b'  '] # used at 4 word boundaries -> 2^4 = 16 combinations
    id_bytes = id_str.encode()
    units = [b'dollars', b'dollar', b'USD', b'bucks', b'dollars US']
    timeframes = [b'by tomorrow', b'by end of tomorrow', b'tomorrow', b'by end of day', b'by end of the day']
    extras = [b'', b' (confirmed)', b' (as agreed)', b' per our agreement']
    puncts = [b'.', b'!', b'']
    closings = [b'', b' Please confirm receipt.', b' Thanks.']
 
    amounts_100 = [b'100', b'one hundred', b'100.00', b'a hundred', b'$100']
    amounts_1M = [b'1,000,000', b'1000000', b'one million', b'a million', b'1M', b'1 million']
 
    def gen_messages(amounts):
        #Yield all variant messages for a given amount list.
        for (pre, name, verb, s1, s2, amount, s3, unit, s4, timeframe, extra, punct, closing) in itertools.product(prefixes, names, verbs, s_opts, s_opts, amounts, s_opts, units, s_opts, timeframes, extras, puncts, closings):
            yield (pre + name + s1 + verb + s2 + id_bytes + s3 + amount + b' ' + unit + s4 + timeframe + extra + punct + closing)
 
    #Phase 1: build lookup table from all M1 variants
    m1_table = {}
    for msg in gen_messages(amounts_100):
        h = proj2hash(msg)
        if h not in m1_table:
            m1_table[h] = msg
 
    m1_count = len(m1_table)
 
    #Phase 2: stream M2 variants, check for collision
    m2_count = 0
    for msg in gen_messages(amounts_1M):
        m2_count += 1
        h = proj2hash(msg)
        if h in m1_table:
            M1 = m1_table[h]
            M2 = msg
            total = m1_count + m2_count
            print(f"[Problem 2] Collision found after {total:,} total evaluations "f"({m1_count:,} M1 hashed, {m2_count:,} M2 tried)")
            print(f"M1: {M1.decode()}")
            print(f"M2: {M2.decode()}")
            print(f"hash(M1) = hash(M2) = {h.hex()}")
            assert proj2hash(M1) == proj2hash(M2), "Check failed!"
            assert M1 != M2, "Messages must be distinct!"
            return M1, M2
 
    print("[Problem 2] No collision found, increase tweak space.")
    return None
 


################################################################################
# Problem 3 SOLUTION
################################################################################

def _floyd_trial(pre):
    #Floyd cycle detection on the sequence x0, f(x0), f^2(x0), ...
    #Returns (total_evals, M1, M2) where proj2hash(M1)==proj2hash(M2), M1!=M2.
    f = proj2hash
 
    #Seed: hash pre to get a 5 byte starting point in the output space.
    x0    = f(pre)
    evals = 1
 
    #Phase 1: detect meeting point
    tortoise = f(x0) #1 eval
    hare = f(f(x0)) #2 evals
    evals += 3
 
    while tortoise != hare:
        tortoise = f(tortoise) #1 eval
        hare = f(f(hare)) #2 evals
        evals += 3
 
    #Phase 2: locate cycle start (mu)
    #Track previous values so we capture the colliding predecessors of x_mu.
    tortoise = x0
    prev_t = None
    prev_h = None
 
    while tortoise != hare:
        prev_t = tortoise
        prev_h = hare
        tortoise = f(tortoise) #1 eval
        hare = f(hare) #1 eval
        evals += 2
 
    #If prev_t is None, mu=0 (cycle starts at x0). 
    #walk one extra step to get a distinct predecessor pair that both map into the cycle entry point.
    if prev_t is None:
        prev_t = x0
        node = f(x0)
        evals += 1
        while f(node) != x0:
            node = f(node)
            evals += 1
        prev_h = node #f(prev_h) == x0 == f(prev_t), but prev_t != prev_h
 
    M1, M2 = prev_t, prev_h
    return evals, M1, M2
 
 
def problem3(id):
    #Run 10 Floyd's trials and return the average number of hash evaluations.
    total_evals = 0
    for digit in b'0123456789':
        pre = bytes([digit]) + id
        evals, M1, M2 = _floyd_trial(pre)
        total_evals += evals
 
    average = total_evals / 10
    print(f"[Problem 3] Average evaluations over 10 trials: {average:.1f}")
    print(f"[Problem 3] Birthday bound (2^20): {2**20}")
    print(f"[Problem 3] Expected Floyd range (3-5x): {3*2**20} - {5*2**20}")
    return average
 
 
 

################################################################################
# Problem 4 SOLUTION
################################################################################

def _decode_f(x, id_bytes):
    #Injective map: 5 byte hash output -> meaningful message.
    #Bit 39 selects meaning, lower 39 bits encode (name, amount_variant, txn_ref).
    val = int.from_bytes(x, 'big')
    meaning = (val >> 39) & 1 #MSB: 0 = $100, 1 = $1M
    v = val & 0x7FFFFFFFFF #lower 39 bits
 
    #Mixed radix: extract small tweaks, remainder becomes a unique ref
    names = [b'Alex', b'ALEX', b'alex']
    amounts_100 = [b'100', b'one hundred', b'$100']
    amounts_1M = [b'1,000,000', b'one million', b'$1M']
 
    name = names[v % 3]
    v //= 3
    amounts = amounts_100 if meaning == 0 else amounts_1M
    amt = amounts[v % 3]
    v //= 3
 
    #Remaining bits (~35) uniquely identify this input, embed as a ref number.
    #This makes f injective: different inputs always produce different messages.
    txn_ref = v #unique across all tuples
 
    return (name + b' owes ' + id_bytes + b' ' + amt + b' dollars by tomorrow. [ref: ' + str(txn_ref).encode() + b']')
 
 
def _floyd_on_H_prime(seed, id_bytes):
    #Floyd's cycle detection on H'(x) = proj2hash(_decode_f(x)).
    #Returns (total_evals, cx, cy) where H'(cx)==H'(cy) and cx!=cy.
    #Because decode_f is injective, this guarantees proj2hash(f(cx))=proj2hash(f(cy)) with f(cx)!=f(cy): a collision in proj2hash.

    def H_prime(x):
        return proj2hash(_decode_f(x, id_bytes)) #1 eval
 
    x0 = seed
    evals = 0
 
    #Phase 1: detect meeting point
    tortoise = H_prime(x0)
    evals += 1
    hare = H_prime(H_prime(x0))
    evals += 2
 
    while tortoise != hare:
        tortoise = H_prime(tortoise)
        evals += 1
        hare = H_prime(H_prime(hare))
        evals += 2
 
    #Phase 2: locate cycle start (mu)
    tortoise = x0
    prev_t = prev_h = None
 
    while tortoise != hare:
        prev_t = tortoise
        prev_h = hare
        tortoise = H_prime(tortoise)
        evals += 1
        hare = H_prime(hare)
        evals += 1
 
    #Handle mu=0 edge case
    if prev_t is None:
        prev_t = x0
        node = H_prime(x0)
        evals += 1
        while H_prime(node) != x0:
            node = H_prime(node)
            evals += 1
        prev_h = node
 
    return evals, prev_t, prev_h
 
 
def problem4(id):
    #Find a useful collision: M1 means '$100', M2 means '$1M', proj2hash(M1)==proj2hash(M2), via Floyd's.
    #Returns (M1, M2).

    id_bytes = id if isinstance(id, bytes) else id.encode()
    total_evals = 0
    attempt = 0
 
    while True:
        attempt += 1
        seed = proj2hash(bytes([attempt & 0xFF]) + id_bytes)
 
        evals, cx, cy = _floyd_on_H_prime(seed, id_bytes)
        total_evals += evals
 
        M1 = _decode_f(cx, id_bytes)
        M2 = _decode_f(cy, id_bytes)
 
        meaning_cx = (int.from_bytes(cx, 'big') >> 39) & 1
        meaning_cy = (int.from_bytes(cy, 'big') >> 39) & 1
 
        #Verify: genuine collision (f injective -> M1 != M2 guaranteed if cx != cy)
        assert M1 != M2, "Bug: injective f should never produce M1==M2 for cx!=cy"
 
        if meaning_cx != meaning_cy:
            assert proj2hash(M1) == proj2hash(M2), "Bug: H' collision should imply proj2hash collision"
            print(f"[Problem 4] Useful collision on attempt {attempt}, "f"total evals: {total_evals:,}")
            print(f"M1 (${'100' if meaning_cx == 0 else '1M'}): {M1.decode()}")
            print(f"M2 (${'100' if meaning_cy == 0 else '1M'}): {M2.decode()}")
            print(f"proj2hash: {proj2hash(M1).hex()}")
            return M1, M2
 

################################################################################
# Main function (testing only)
################################################################################
if __name__ == "__main__":
    import time
    TEST_ID = b'soh'

    print("Problem 1:")
    avg = problem1(TEST_ID)
    print(f"Passed with average {avg:.0f} evaluations whereas expected ~{2**20}\n")

    print("Problem 2:")
    result = problem2(TEST_ID)
    M1, M2 = result
    print(f"Passed with collision at hash: {proj2hash(M1).hex()}\n")

    print("Problem 3:")
    t = time.time()
    avg3 = problem3(TEST_ID)
    elapsed = time.time() - t
    print(f"Passed with average {avg3:.0f} evaluations in {elapsed:.1f}s\n")

    print("Problem 4:")
    result4 = problem4(TEST_ID)
    M1, M2 = result4 
    print(f"Passed with collision at hash: {proj2hash(M1).hex()}\n")