import random
from collections import defaultdict

#V = 65536
#E = 262144
V = 64
E = 128

edges = defaultdict(lambda: 0)
while len(edges) < E:
    # Length of cycle
    n = random.randint(1,min(5,E-len(edges)))

    nodes = [random.randint(0,V-1) for _ in range(n)]

    # Amount
    amt = random.randint(1,100)
    
    for (src,dst) in zip(nodes, nodes[1:]+nodes[:1]):
        edges[(src,dst)] += amt

edges = [[src,dst,amt] for (src,dst),amt in edges.items() if src != dst]
edges += [[0,0,0]]*(E-len(edges))

def kerckhoff(edges):
    v = defaultdict(lambda: 0)
    for (src,dst,amt) in edges:
        v[src] -= amt
        v[dst] += amt
    for val in v.values():
        assert(val == 0)
    print('ok')
kerckhoff(edges)

print(edges)
#for e in edges:
#    print(list(e))
