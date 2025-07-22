import numpy as np
np.savetxt("q_table.csv", np.load("q_table.npy"), delimiter=",")