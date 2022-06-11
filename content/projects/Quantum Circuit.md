+++
title = "Quantum SVM for Supernova Classification"
date = 2022-06-10

[taxonomies]
tags = ["Python", "Quantum computing", "ML"]
+++

I thank Peters, et al.(2021) for their work [1].

April 2022

### Imports

import numpy as np
import paddle
from paddle_quantum.circuit import UAnsatz
from sklearn import svm
from typing import NamedTuple
from matplotlib import pyplot as plt
import time
import warnings

### Set-up
Fixing random state for reproducibility and suppress warnings

```python 
np.random.seed(999)
warnings.filterwarnings('ignore')
```

Define a struct to encapsulate necessary circuit information such as the number of qubits, the depth, etc. This allows effective iterations with different sets of parameters.

```python 
class CircuitInfo(NamedTuple):
    N: int
    DEPTH: int
    Ntrain: int
    Ntest: int 
```

Instantiate a global struct with 4 qubits, DEPTH = 1, 6 training data, 100 testing data (those parameters will not result in a very good prediction, as will be seen later on; those parameters will be changed)

```python 
circuit_info = CircuitInfo(4, 1, 6, 100)
```

Note that DEPTH is depth of the circuit for $U(x_i)$ by treating the following as a single unit. This convention can be seen in __[ Baidu Paddel Quantum -- Quantum Neural Network, Built-in Circuits](https://qml.baidu.com/quick-start/quantum-neural-network.html#2-built-in-circuit-templates)__ (the picture right underneath Eq 3.).
```
--Rx----Ry----Rz----Rxx----Ryy----------------
                     |      |                                
--Rx----Ry----Rz----Rxx----Ryy----Rxx----Ryy--
                                   |      |      
--Rx----Ry----Rz----Rxx----Ryy----Rxx----Ryy--
                     |      |                                                 
--Rx----Ry----Rz----Rxx----Ryy----------------
```

### Dataset generation
Generate a binary classification data set. Note that the data generated here does not necessarily represent any real supernova clusters as I am not well trained enough in astronomy to generate realistic dataset on my own. Kaggle has one but I think it is not well collected. Taking into considertation that how the data is generated is not crucial in presenting the core algorithm, it is okay to do that. The function below puts the data into a 3d array which may have differed from what Peters, et al.(2021) [1] have done in their paper. However, it should be noted that the data can be reshaped to the desired dimensions. 

```python 
def data_generator(boundary_gap):
    X = []
    Y = []
    for k in range(circuit_info.Ntrain + circuit_info.Ntest):
        # generate two different types of data
        vec = []
        if (np.random.rand() < boundary_gap):
            vec = vec + [np.random.rand() for _ in range(3*circuit_info.N*circuit_info.DEPTH)]
            Y.append(1)
        else:
            vec = vec + [np.random.rand() for _ in range(circuit_info.N*circuit_info.DEPTH)]
            vec = vec + [np.random.rand()*10 for _ in range(2*circuit_info.N*circuit_info.DEPTH)]
            Y.append(0)
        X.append(vec)
    X = np.array(X).astype("float64")
    Y = np.array(Y).astype("float64")
    return X[0:circuit_info.Ntrain], Y[0:circuit_info.Ntrain], X[circuit_info.Ntrain:], Y[circuit_info.Ntrain:]
```

Notice that this could serve as reductions from a higher dimentional data -- reduce original features into ```
3*circuit_info.N*circuit_info.DEPTH``` number of features. The values resulted by the reductions are distributed (```np.random```). Some sample reduction functions are shown below which are not necessary in this case (the numbers are randomized before and after the reduction).

```python 
# A sample reduction function to reduce the first and second features into one
def a_first_reduction(v, w):
    return np.sqrt(v**2+w**2)/4

# A sample reduction function to reduce the last and second last features into one
def a_second_reduction(v, w):
    return np.sqrt(v**2-w**2)/2
```

### SVM with Quantum circuits
The two functions below are variations of the ```q_kernel_estimator``` and ```q_kernel_matrix``` shown in __[Baidu Paddel Quantum -- Quantum Kernel Method](https://qml.baidu.com/tutorials/machine-learning/quantum-kernel-methods.html#2-kernel-based-classification-with-paddle-quantum)__, with a difference that **two disconnected** circuits are returned, ```cir1``` and ```cir2```, representing the circuits for $U(x_i)\text{ and }U(x_j)$
respectively. ```fin_state2.conj()``` is the $U^\dagger(x_i)$. Those two functions are used to generate the customized kernel matrix.

```python 
def q_kernel_estimator(x1, x2):
    theta1 = paddle.to_tensor(x1)
    theta2 = paddle.to_tensor(x2)
    cir1 = circuit(theta1)
    cir2 = circuit(theta2)
    fin_state1 = cir1.run_state_vector()
    fin_state2 = cir2.run_state_vector()
    return (fin_state2.conj() * fin_state1).real().numpy()[0]

def q_kernel_matrix(X1, X2):
    return np.array([[q_kernel_estimator(x1, x2) for x2 in X2] for x1 in X1])
```

### Circuit
The below function generates a quantum circuit based on the description in **II. QUANTUM KERNEL SUPPORT VECTOR
MACHINES, B.Circuit Design** [1] and the algorithm is templated by __[Baidu Paddel Quantum -- Quick start, Frequently used function, VQA basic structure](https://qml.baidu.com/quick-start/frequently-used-functions-in-paddle-quantum.html#2-8-vqa-basic-structure-1----create-your-own-quantum-circuit-as-a-function)__, with one major obstacle -- {% katex(block=true) %}\sqrt{i\mathbf{SWAP}}{% end %} is not native in ```paddle_quantum```. However, upon further investigation, it can be genereted via a combination of two native gates:
{% katex(block=true) %}
\sqrt{i\mathbf{SWAP}}=R_{xx}\big(\frac{-\pi}{4}\big)R_{yy}\big(\frac{-\pi}{4}\big)
{% end %}
```python 
def circuit(theta):
    cir = UAnsatz(circuit_info.N)
    theta = paddle.to_tensor(np.reshape(theta, (circuit_info.N, circuit_info.DEPTH, 3)))
    for dep in range(circuit_info.DEPTH): 
        for n in range(circuit_info.N): 
            cir.rx(theta[n][dep][0], n)  # add an Rx gate to the n-th qubit
            cir.ry(theta[n][dep][1], n)  # add an Ry gate to the n-th qubit
            cir.rz(theta[n][dep][2], n)  # add an Rz gate to the n-th qubit 
        for n in range(circuit_info.N - 1):
            if n % 2 == 0 and (n < circuit_info.N):
                # the following two lines generate the (forward) square root of a iswap unit
                # as there is no native implementation 
                cir.rxx(paddle.to_tensor(np.array([-np.pi/4])), [n, n+1])
                cir.ryy(paddle.to_tensor(np.array([-np.pi/4])), [n, n+1])
        for n in range(circuit_info.N - 1):
            if n % 2 == 1 and (n < circuit_info.N - 1):
                cir.rxx(paddle.to_tensor(np.array([-np.pi/4])), [n, n+1])
                cir.ryy(paddle.to_tensor(np.array([-np.pi/4])), [n, n+1])
    return cir
```
An example circuit generated by the above code is as follows
```
--Rx(0.528)----Ry(0.119)----Rz(0.640)----Rxx(-0.7)----Ryy(-0.7)----------------------------
                                             |            |                                
--Rx(0.091)----Ry(0.332)----Rz(0.427)----Rxx(-0.7)----Ryy(-0.7)----Rxx(-0.7)----Ryy(-0.7)--
                                                                       |            |      
--Rx(5.544)----Ry(6.281)----Rz(6.974)----Rxx(-0.7)----Ryy(-0.7)----Rxx(-0.7)----Ryy(-0.7)--
                                             |            |                                
--Rx(7.899)----Ry(1.319)----Rz(3.428)----Rxx(-0.7)----Ryy(-0.7)----Rxx(-0.7)----Ryy(-0.7)--
                                                                       |            |      
--Rx(2.016)----Ry(7.073)----Rz(0.334)----Rxx(-0.7)----Ryy(-0.7)----Rxx(-0.7)----Ryy(-0.7)--
                                             |            |                                
--Rx(9.093)----Ry(4.052)----Rz(7.604)----Rxx(-0.7)----Ryy(-0.7)----------------------------
```
The example circuit is for a 18-dimensional data.

### Training results
```result``` calls the SVM implemented with the custumized circuit, predicts for the testing set, and returns the accuracies for the trainning and testing sets. 
```python
def result():
    svm_qke = svm.SVC(kernel=q_kernel_matrix)
    X_train, y_train, X_test, y_test = data_generator(0.5)
    svm_qke.fit(X_train, y_train)
    predict_svm_qke_train = svm_qke.predict(X_train)
    predict_svm_qke_test = svm_qke.predict(X_test)
    accuracy_train = np.array(predict_svm_qke_train == y_train, dtype=int).sum()/len(y_train)
    accuracy_test = np.array(predict_svm_qke_test == y_test, dtype=int).sum()/len(y_test)
    return accuracy_train, accuracy_test
```
```change_Ntrain``` changes the number of data in the training set ($[6, 16)$ in steps of 2)  while keeping the other parameters constant.
```python
def change_Ntrain():
    global circuit_info 
    # temp holds the attribute that is changing for recovery
    temp = circuit_info.Ntrain
    Ntrain_lst = range(temp, temp + 10, 2)
    res_train = []
    res_test = []
    time_elapsed = []
    for k in Ntrain_lst:
        circuit_info = CircuitInfo(circuit_info.N, circuit_info.DEPTH, k, circuit_info.Ntest)
        start = time.time()
        a, b = result()
        end = time.time()
        res_train.append(a)
        res_test.append(b)
        time_elapsed.append(end - start)
    fig, ax = plt.subplots(1, 3)
    ax[0].scatter(Ntrain_lst, res_train, marker='o')
    ax[0].set_title('Train')
    ax[1].scatter(Ntrain_lst, res_test, marker='*')
    ax[1].set_title('Test')
    ax[2].scatter(Ntrain_lst, time_elapsed, marker='v')
    ax[2].set_title('Time(s)')
    circuit_info = CircuitInfo(circuit_info.N, circuit_info.DEPTH, temp, circuit_info.Ntest)
```
```change_N``` changes the number of qubits ($[4, 15)$ in steps of 2) while keeping the other parameters constant.
```python
def change_N():
    global circuit_info 
    # temp holds the attribute that is changing for recovery
    temp = circuit_info.N
    N_lst = range(temp, temp + 11, 2)
    res_train = []
    res_test = []
    time_elapsed = []
    for k in N_lst:
        circuit_info = CircuitInfo(k, circuit_info.DEPTH, circuit_info.Ntrain, circuit_info.Ntest)
        start = time.time()
        a, b = result()
        end = time.time()
        res_train.append(a)
        res_test.append(b)
        time_elapsed.append(end - start)
    fig, ax = plt.subplots(1, 3)
    ax[0].scatter(N_lst, res_train, marker='o')
    ax[0].set_title('Train')
    ax[1].scatter(N_lst, res_test, marker='*')
    ax[1].set_title('Test')
    ax[2].scatter(N_lst, time_elapsed, marker='v')
    ax[2].set_title('Time(s)')
    circuit_info = CircuitInfo(temp, circuit_info.DEPTH, circuit_info.Ntrain, circuit_info.Ntest)
```
```change_DEPTH``` changes the DEPTH of the circuit ($[1, 6)$ in steps of 1) while keeping the other parameters constant.
```python
def change_DEPTH():
    global circuit_info 
    # temp holds the attribute that is changing for recovery
    temp = circuit_info.DEPTH
    DEPTH_lst = range(temp, temp + 5)
    res_train = []
    res_test = []
    time_elapsed = []
    for k in DEPTH_lst:
        circuit_info = CircuitInfo(circuit_info.N, k, circuit_info.Ntrain, circuit_info.Ntest)
        start = time.time()
        a, b = result()
        end = time.time()
        res_train.append(a)
        res_test.append(b)
        time_elapsed.append(end - start)
    fig, ax = plt.subplots(1, 3)
    ax[0].scatter(DEPTH_lst, res_train, marker='o')
    ax[0].set_title('Train')
    ax[1].scatter(DEPTH_lst, res_test, marker='*')
    ax[1].set_title('Test')
    ax[2].scatter(DEPTH_lst, time_elapsed, marker='v')
    ax[2].set_title('Time(s)')
    circuit_info = CircuitInfo(circuit_info.N, temp, circuit_info.Ntrain, circuit_info.Ntest)
```
Call the three functions and visualize the results. (NOTE: do not run those on Jupyter, they are pretty slow. I have to use 3 different consoles to run all three of them concurrently.)

 ```python
change_Ntrain()
```

![1.png](https://jxuali.github.io/contents/projects/pics/svm/svm1.png)

```python
change_N()
```

![2.png](https://jxuali.github.io/contents/projects/pics/svm/svm2.png)

```python
change_DEPTH()
```

![3.png](https://jxuali.github.io/contents/projects/pics/svm/svm3.png)

[1] Evan Peters, João Caldeira, Alan Ho, Stefan Leichenauer, Masoud Mohseni, Hartmut Neven, Panagiotis Spentzouris, Doug Strain, and Gabriel N. Perdue, Machine learning of high dimensional data on a noisy quantum processor (2021), arXiv: https://arxiv.org/abs/2101.09581