import time
import csv

from T2_DiffieHellman_1805006 import *

def do_instance(bits_index, instance):
    k=bits[bits_index]
    
    t_0=time.perf_counter_ns()
    
    p = generate_kbit_safe_prime(k)
    # print("p:",p)
    
    t_p=time.perf_counter_ns()
    
    q = p>>1
    # print("q:",q)
    g = generate_primitive_root_safe_prime(p, (p-1)/4, (p-1)/2)
    # print("g:",g)
    
    t_g=time.perf_counter_ns()
    
    a = generate_kbit_prime((k>>1)+1)
    t_a=time.perf_counter_ns()
    
    b = generate_kbit_prime((k>>1)+1)
    
    t_b=time.perf_counter_ns()
    # print("a:",a)
    # print("b:",b)
    
    A = modular_exponent(g,a,p)
    t_A=time.perf_counter_ns()
    B = modular_exponent(g,b,p)
    t_B=time.perf_counter_ns()
    # print("A:",A, modular_exponent(g,a,p))
    # print("B:",B, modular_exponent(g,b,p))
    
    X = modular_exponent(B,a,p)
    t_X=time.perf_counter_ns()
    Y = modular_exponent(A,b,p)
    t_Y=time.perf_counter_ns()
    # print("X:",X ,modular_exponent(B,a,p))
    # print("Y:",Y, modular_exponent(A,b,p))
    
    
    dt_p = (t_p-t_0)/1000000
    dt_g = (t_g-t_p)/1000000
    dt_a = (t_a-t_g)/1000000
    dt_b = (t_b-t_a)/1000000
    dt_A = (t_A-t_b)/1000000
    dt_B = (t_B-t_A)/1000000
    dt_X = (t_X-t_B)/1000000
    dt_Y = (t_Y-t_X)/1000000
    times[bits_index][instance] = [dt_p, dt_g, dt_a, dt_b, dt_A, dt_B, dt_X, dt_Y]
    
    
    # print("dt_p:", dt_p)
    # print("dt_g:", dt_g)
    # print("dt_a:", dt_a)
    # print("dt_b:", dt_b)
    # print("dt_A:", dt_A)
    # print("dt_B:", dt_B)
    # print("dt_X:", dt_X)
    # print("dt_Y:", dt_Y)
    # print("p:", p)
    # print("q:", q)
    # print("g:", g)
    # print("a:", a)
    # print("b:", b)
    # print("A:", A)
    # print("B:", B)
    # print("X:", X)
    # print("Y:", Y)
    
    return dt_p, dt_g, dt_a, dt_b, dt_A, dt_B, dt_X, dt_Y
    
# do_instance(128)


bits =[128,192,256]
# times[bits][instance][p,g,a,b,A,B,X,Y]
times = []
def do_instances(instances):
    for i in range(3):
        times.append([])
        for j in range(instances):
            times[i].append([])
            do_instance(i,j)
            # print("done",i,j)

avg_times=[]
def find_avg_times(instances):
    avg_times.append([])
    avg_times[0] = ["p","g","a","b","A","B","X","Y"]
    for i in range(3):
        avg_times.append([])
        for k in range(8):
            temp = 0
            for j in range(instances):
                temp+=times[i][j][k]
            avg_times[i+1].append(temp/instances)
    for i in range(3):
        print("avg_times[",bits[i],"]:",avg_times[i+1])


            
def write_to_csv_file(filename="DH_times.csv", data=avg_times):
    with open(filename, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(data)

instance_num = int(input("Enter number of instances: "))
do_instances(instance_num)
find_avg_times(instance_num)
write_to_csv_file()
