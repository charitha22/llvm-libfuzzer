import matplotlib.pyplot as plt
import numpy as np


def plot_graph(DATA):
    # Create plots with pre-defined labels.
    # Alternatively, you can pass labels explicitly when calling `legend`.
    fig, ax = plt.subplots()
    ax.plot(DATA[0][0], DATA[0][1], 'r', label='DiffFuzz')
    ax.plot(DATA[1][0], DATA[1][1], 'b', label='SlowFuzz')
    ax.plot(DATA[2][0], DATA[2][1], 'g', label='PerfFuzz')
    

    # Now add the legend with some customizations.
    legend = ax.legend(loc='lower right', shadow=True)

    # The frame is matplotlib.patches.Rectangle instance surrounding the legend.
    frame = legend.get_frame()
    frame.set_facecolor('0.90')

    # Set the fontsize
    for label in legend.get_texts():
        label.set_fontsize('large')

    for label in legend.get_lines():
        label.set_linewidth(1.5)  # the legend line width
    plt.xlabel("Time(s)")
    plt.ylabel("Instruction Count")
    plt.show()


def process_data(data):

    max_time = 0
    for d in data:
        x_dim = d[0]
        max_time = max(max_time, x_dim[-1])

    # print max_time
    for d in data:
        x_dim = d[0]
        y_dim = d[1]
        
        if x_dim[-1] < max_time:
            t = x_dim[-1]
            max_y = y_dim[-1]
            while t < max_time-10:
                x_dim.append(t+10)
                y_dim.append(max_y)
                t = t+10
        print d
    
    return data


data = []
for t in ["x", "slow", "perf"]:
    tool = t
    f = open(tool+".data", "r")
    xdata = []
    ydata = []

    for l in f.readlines():
        words = l.rstrip().split(",")
        xdata.append(float(words[0]))
        ydata.append(int(words[1]))

    data.append([xdata, ydata])




plot_data = process_data(data)

plot_graph(plot_data)


