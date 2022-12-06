import matplotlib.pyplot as plt

# creating the dataset
data = {'IBE - Setup':1.571673, 'IBE - Extract':0.792551, 'IBE - Encrypt':8.947755,
        'IBE - Decrypt':5.904935}

functions = list(data.keys())
runtimes = list(data.values())
  
fig = plt.figure(figsize = (10, 5))
 
# creating the bar plot
plt.bar(functions, runtimes, color ='royalblue')
 
plt.ylabel("Milliseconds")
plt.title("Benchmarking of IBE implementation")
plt.show()