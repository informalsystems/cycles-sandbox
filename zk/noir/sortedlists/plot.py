import glob
import matplotlib.pyplot as plt
import re
import numpy as np

ns = np.array(range(4,11))
real_times = []
cpu_times = []
circuit_size = []
for n in ns:
    # Read the proving time stamps
    lines = open(f'build_circuits/time_proof_{n}.txt')
    for line in lines:
        if 'real' in line:
            min,sec = re.search(r'([.\d]+)m([.\d]+)s', line).group(1,2)
            print(line, min,sec)
            real_times.append(float(min)*60+float(sec))
        if 'user' in line:
            min,sec = re.search(r'([.\d]+)m([.\d]+)s', line).group(1,2)
            print(line, min,sec)
            cpu_times.append(float(min)*60+float(sec))
    
    # Examine the infos
    info = open(f'build_circuits/info_{n}.txt').read()

    # | 2^4     | Bounded { width: 3 } | 439          | 12005                |
    x = re.search('| (2\^\d+) |', info).group(1)
    opcodes,backendsize = re.findall(r'\d+', info)[-2:]
    print(opcodes, backendsize)
    circuit_size.append(int(backendsize))
    
plt.figure(0); plt.clf();
plt.plot(2**ns, circuit_size);
plt.title('Proving committed lists are sorted: Circuit Size vs Input Size')
plt.xlabel('input size')
plt.ylabel('Backend Circuit Size')

plt.figure(1); plt.clf();
plt.plot(2**ns, cpu_times);
plt.title('Proving committed lists are sorted: total CPU time')
plt.xlabel('input size')
plt.ylabel('Total CPU time')

plt.figure(2); plt.clf();
plt.plot(2**ns, real_times);
plt.title('Proving committed lists are sorted: Real time')
plt.xlabel('input size')
plt.ylabel('Elapsed time')
plt.show()
    
